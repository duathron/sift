"""Alert filtering module for sift — boolean DSL for filtering Cluster objects.

Supports filter expressions like:
  priority >= HIGH
  category IN (malware, phishing)
  ioc_count > 5 AND priority >= MEDIUM
  NOT category IN (false_positive) OR alert_count <= 3
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional, Protocol

from sift.models import Cluster, ClusterPriority


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class FilterError(Exception):
    """Base exception for filtering errors."""

    pass


class FilterSyntaxError(FilterError):
    """Raised when filter query syntax is invalid."""

    pass


class FilterEvalError(FilterError):
    """Raised when filter evaluation encounters type or value errors."""

    pass


# ---------------------------------------------------------------------------
# Token definitions
# ---------------------------------------------------------------------------


class TokenType(str, Enum):
    """Token types for filter expression lexer."""

    # Operators
    LPAREN = "LPAREN"
    RPAREN = "RPAREN"
    AND = "AND"
    OR = "OR"
    NOT = "NOT"
    IN = "IN"
    NOT_IN = "NOT_IN"

    # Comparisons
    EQ = "EQ"
    NE = "NE"
    LT = "LT"
    LE = "LE"
    GT = "GT"
    GE = "GE"

    # Values
    IDENTIFIER = "IDENTIFIER"
    NUMBER = "NUMBER"
    STRING = "STRING"

    # End of input
    EOF = "EOF"


@dataclass
class Token:
    """A single token from the lexer."""

    type: TokenType
    value: Any
    position: int


# ---------------------------------------------------------------------------
# Lexer
# ---------------------------------------------------------------------------


class Lexer:
    """Tokenizes a filter expression string."""

    KEYWORDS = {
        "AND": TokenType.AND,
        "OR": TokenType.OR,
        "NOT": TokenType.NOT,
        "IN": TokenType.IN,
    }

    def __init__(self, query: str):
        self.query = query.strip()
        self.pos = 0
        self.current_char = self.query[0] if query else None

    def error(self, msg: str) -> None:
        raise FilterSyntaxError(f"Lexer error at position {self.pos}: {msg}")

    def advance(self) -> None:
        self.pos += 1
        if self.pos < len(self.query):
            self.current_char = self.query[self.pos]
        else:
            self.current_char = None

    def peek(self, offset: int = 1) -> Optional[str]:
        peek_pos = self.pos + offset
        if peek_pos < len(self.query):
            return self.query[peek_pos]
        return None

    def skip_whitespace(self) -> None:
        while self.current_char is not None and self.current_char.isspace():
            self.advance()

    def read_number(self) -> Token:
        start_pos = self.pos
        num_str = ""

        # Handle leading negative sign
        if self.current_char == "-":
            num_str += self.current_char
            self.advance()

        # Read digits and optional decimal point
        has_decimal = False
        while self.current_char is not None and (self.current_char.isdigit() or self.current_char == "."):
            if self.current_char == ".":
                if has_decimal:
                    break  # Only one decimal point allowed
                has_decimal = True
            num_str += self.current_char
            self.advance()

        try:
            value = float(num_str) if has_decimal else int(num_str)
        except ValueError:
            self.error(f"Invalid number: {num_str}")

        return Token(TokenType.NUMBER, value, start_pos)

    def read_identifier(self) -> Token:
        start_pos = self.pos
        ident = ""
        while self.current_char is not None and (self.current_char.isalnum() or self.current_char == "_"):
            ident += self.current_char
            self.advance()

        upper_ident = ident.upper()
        if upper_ident in self.KEYWORDS:
            return Token(self.KEYWORDS[upper_ident], upper_ident, start_pos)

        return Token(TokenType.IDENTIFIER, ident, start_pos)

    def read_string(self) -> Token:
        start_pos = self.pos
        quote_char = self.current_char
        self.advance()
        value = ""
        while self.current_char is not None and self.current_char != quote_char:
            if self.current_char == "\\":
                self.advance()
                if self.current_char is None:
                    self.error("Unterminated string escape")
                value += self.current_char
            else:
                value += self.current_char
            self.advance()

        if self.current_char != quote_char:
            self.error("Unterminated string")
        self.advance()

        return Token(TokenType.STRING, value, start_pos)

    def get_next_token(self) -> Token:
        while self.current_char is not None:
            if self.current_char.isspace():
                self.skip_whitespace()
                continue

            if self.current_char == "(":
                token = Token(TokenType.LPAREN, "(", self.pos)
                self.advance()
                return token

            if self.current_char == ")":
                token = Token(TokenType.RPAREN, ")", self.pos)
                self.advance()
                return token

            if self.current_char == ",":
                # Commas are special: we'll use them as implicit separators
                token = Token(TokenType.IDENTIFIER, ",", self.pos)
                self.advance()
                return token

            if self.current_char == "=" and self.peek() == "=":
                token = Token(TokenType.EQ, "==", self.pos)
                self.advance()
                self.advance()
                return token

            if self.current_char == "!" and self.peek() == "=":
                token = Token(TokenType.NE, "!=", self.pos)
                self.advance()
                self.advance()
                return token

            if self.current_char == "<" and self.peek() == "=":
                token = Token(TokenType.LE, "<=", self.pos)
                self.advance()
                self.advance()
                return token

            if self.current_char == "<":
                token = Token(TokenType.LT, "<", self.pos)
                self.advance()
                return token

            if self.current_char == ">" and self.peek() == "=":
                token = Token(TokenType.GE, ">=", self.pos)
                self.advance()
                self.advance()
                return token

            if self.current_char == ">":
                token = Token(TokenType.GT, ">", self.pos)
                self.advance()
                return token

            if self.current_char == "-" or self.current_char.isdigit():
                # Check if this is a negative number (minus followed by digit)
                if self.current_char == "-" and self.peek() is not None and self.peek().isdigit():
                    return self.read_number()
                elif self.current_char.isdigit():
                    return self.read_number()
                else:
                    # Just a minus sign, treat as error for now
                    self.error(f"Unexpected character: {self.current_char}")

            if self.current_char in ("'", '"'):
                return self.read_string()

            if self.current_char.isalpha() or self.current_char == "_":
                token = self.read_identifier()
                # Check for NOT IN pattern
                if token.type == TokenType.NOT:
                    saved_pos = self.pos
                    self.skip_whitespace()
                    if self.current_char is not None and self.current_char.isalpha():
                        next_token = self.read_identifier()
                        if next_token.type == TokenType.IN:
                            return Token(TokenType.NOT_IN, "NOT IN", token.position)
                    self.pos = saved_pos
                    self.current_char = self.query[self.pos] if self.pos < len(self.query) else None
                return token

            self.error(f"Unexpected character: {self.current_char}")

        return Token(TokenType.EOF, None, self.pos)


# ---------------------------------------------------------------------------
# AST Nodes
# ---------------------------------------------------------------------------


class ASTNode(Protocol):
    """Base protocol for AST nodes."""

    def evaluate(self, cluster: Cluster) -> bool:
        """Evaluate this node against a cluster."""
        ...


@dataclass
class ComparisonNode:
    """AST node for comparison operations."""

    field: str
    operator: str
    value: Any

    def evaluate(self, cluster: Cluster) -> bool:
        actual = self._get_field_value(cluster)
        return self._compare(actual, self.operator, self.value)

    def _get_field_value(self, cluster: Cluster) -> Any:
        if self.field == "priority":
            return cluster.priority
        elif self.field == "category":
            return cluster.alerts[0].category if cluster.alerts and cluster.alerts[0].category else ""
        elif self.field == "ioc_count":
            return len(cluster.iocs)
        elif self.field == "alert_count":
            return len(cluster.alerts)
        elif self.field == "confidence_score":
            return cluster.confidence
        else:
            raise FilterEvalError(f"Unknown field: {self.field}")

    def _compare(self, actual: Any, op: str, expected: Any) -> bool:
        if op == "==":
            if isinstance(actual, ClusterPriority) and isinstance(expected, str):
                return actual.value == expected.upper()
            return actual == expected

        if op == "!=":
            if isinstance(actual, ClusterPriority) and isinstance(expected, str):
                return actual.value != expected.upper()
            return actual != expected

        if op == "<":
            return self._numeric_compare(actual, expected, lambda a, e: a < e)
        if op == "<=":
            return self._numeric_compare(actual, expected, lambda a, e: a <= e)
        if op == ">":
            return self._numeric_compare(actual, expected, lambda a, e: a > e)
        if op == ">=":
            return self._numeric_compare(actual, expected, lambda a, e: a >= e)

        raise FilterEvalError(f"Unknown operator: {op}")

    def _numeric_compare(self, actual: Any, expected: Any, comparator) -> bool:
        if isinstance(actual, ClusterPriority):
            priority_order = {
                "NOISE": 0,
                "LOW": 1,
                "MEDIUM": 2,
                "HIGH": 3,
                "CRITICAL": 4,
            }
            actual_val = priority_order.get(actual.value)
            if isinstance(expected, str):
                expected_val = priority_order.get(expected.upper())
            elif isinstance(expected, (int, float)):
                # Allow numeric comparison if expected is a number
                raise FilterEvalError(f"Cannot compare priority to numeric value: {actual} vs {expected}")
            else:
                expected_val = None

            if actual_val is None or expected_val is None:
                raise FilterEvalError(f"Invalid priority value")
            return comparator(actual_val, expected_val)

        if not isinstance(actual, (int, float)) or not isinstance(expected, (int, float)):
            raise FilterEvalError(f"Cannot compare non-numeric types: {type(actual)} vs {type(expected)}")

        return comparator(actual, expected)


@dataclass
class SetMembershipNode:
    """AST node for IN / NOT IN operations."""

    field: str
    operator: str  # "IN" or "NOT IN"
    values: list[str]

    def evaluate(self, cluster: Cluster) -> bool:
        actual = self._get_field_value(cluster)
        matches = any(actual.lower() == v.lower() for v in self.values)
        return matches if self.operator == "IN" else not matches

    def _get_field_value(self, cluster: Cluster) -> str:
        if self.field == "category":
            return cluster.alerts[0].category if cluster.alerts and cluster.alerts[0].category else ""
        else:
            raise FilterEvalError(f"SET membership only supported for 'category' field, got: {self.field}")


@dataclass
class UnaryOpNode:
    """AST node for NOT operations."""

    operator: str  # "NOT"
    operand: ASTNode

    def evaluate(self, cluster: Cluster) -> bool:
        return not self.operand.evaluate(cluster)


@dataclass
class BinaryOpNode:
    """AST node for AND / OR operations."""

    operator: str  # "AND" or "OR"
    left: ASTNode
    right: ASTNode

    def evaluate(self, cluster: Cluster) -> bool:
        if self.operator == "AND":
            return self.left.evaluate(cluster) and self.right.evaluate(cluster)
        elif self.operator == "OR":
            return self.left.evaluate(cluster) or self.right.evaluate(cluster)
        raise FilterEvalError(f"Unknown binary operator: {self.operator}")


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


class Parser:
    """Recursive descent parser for filter expressions."""

    def __init__(self, lexer: Lexer):
        self.lexer = lexer
        self.current_token = self.lexer.get_next_token()

    def error(self, msg: str) -> None:
        raise FilterSyntaxError(f"Parser error at token {self.current_token}: {msg}")

    def eat(self, token_type: TokenType) -> None:
        if self.current_token.type == token_type:
            self.current_token = self.lexer.get_next_token()
        else:
            self.error(f"Expected {token_type}, got {self.current_token.type}")

    def parse(self) -> ASTNode:
        node = self.parse_or()
        if self.current_token.type != TokenType.EOF:
            self.error(f"Expected EOF, got {self.current_token.type}")
        return node

    def parse_or(self) -> ASTNode:
        node = self.parse_and()

        while self.current_token.type == TokenType.OR:
            self.eat(TokenType.OR)
            node = BinaryOpNode("OR", node, self.parse_and())

        return node

    def parse_and(self) -> ASTNode:
        node = self.parse_not()

        while self.current_token.type == TokenType.AND:
            self.eat(TokenType.AND)
            node = BinaryOpNode("AND", node, self.parse_not())

        return node

    def parse_not(self) -> ASTNode:
        if self.current_token.type == TokenType.NOT:
            self.eat(TokenType.NOT)
            return UnaryOpNode("NOT", self.parse_not())

        return self.parse_primary()

    def parse_primary(self) -> ASTNode:
        if self.current_token.type == TokenType.LPAREN:
            self.eat(TokenType.LPAREN)
            node = self.parse_or()
            self.eat(TokenType.RPAREN)
            return node

        return self.parse_comparison()

    def parse_comparison(self) -> ASTNode:
        field = self.parse_field()

        if self.current_token.type == TokenType.NOT_IN:
            self.eat(TokenType.NOT_IN)
            values = self.parse_set()
            return SetMembershipNode(field, "NOT IN", values)

        if self.current_token.type == TokenType.IN:
            self.eat(TokenType.IN)
            values = self.parse_set()
            return SetMembershipNode(field, "IN", values)

        if self.current_token.type in (TokenType.EQ, TokenType.NE, TokenType.LT, TokenType.LE, TokenType.GT, TokenType.GE):
            op_token = self.current_token
            self.eat(op_token.type)
            value = self.parse_value()
            op_map = {
                TokenType.EQ: "==",
                TokenType.NE: "!=",
                TokenType.LT: "<",
                TokenType.LE: "<=",
                TokenType.GT: ">",
                TokenType.GE: ">=",
            }
            return ComparisonNode(field, op_map[op_token.type], value)

        self.error(f"Expected comparison operator, got {self.current_token.type}")

    def parse_field(self) -> str:
        if self.current_token.type != TokenType.IDENTIFIER:
            self.error(f"Expected field name, got {self.current_token.type}")
        field = self.current_token.value
        self.eat(TokenType.IDENTIFIER)
        return field

    def parse_value(self) -> Any:
        if self.current_token.type == TokenType.NUMBER:
            value = self.current_token.value
            self.eat(TokenType.NUMBER)
            return value

        if self.current_token.type == TokenType.IDENTIFIER:
            value = self.current_token.value
            self.eat(TokenType.IDENTIFIER)
            return value

        if self.current_token.type == TokenType.STRING:
            value = self.current_token.value
            self.eat(TokenType.STRING)
            return value

        self.error(f"Expected value, got {self.current_token.type}")

    def parse_set(self) -> list[str]:
        self.eat(TokenType.LPAREN)
        values = []

        if self.current_token.type != TokenType.RPAREN:
            values.append(str(self.parse_value()))

            while self.current_token.type == TokenType.IDENTIFIER and self.current_token.value == ",":
                self.eat(TokenType.IDENTIFIER)  # consume comma
                if self.current_token.type == TokenType.RPAREN:
                    # trailing comma is ok
                    break
                values.append(str(self.parse_value()))

        self.eat(TokenType.RPAREN)
        return values


# ---------------------------------------------------------------------------
# Filter Parser (public API)
# ---------------------------------------------------------------------------


class FilterParser:
    """Public API for parsing filter queries."""

    @staticmethod
    def parse(query: str) -> AlertFilter:
        """Parse a filter query and return an AlertFilter object.

        Args:
            query: Filter expression string (e.g., "priority >= HIGH AND category IN (malware)")

        Returns:
            An AlertFilter that can evaluate clusters.

        Raises:
            FilterSyntaxError: If the query syntax is invalid.
        """
        lexer = Lexer(query)
        parser = Parser(lexer)
        ast = parser.parse()
        return SimpleFilter(query, ast)


# ---------------------------------------------------------------------------
# Filter Protocol & Implementations
# ---------------------------------------------------------------------------


class AlertFilter(Protocol):
    """Protocol for alert filter objects."""

    def matches(self, cluster: Cluster) -> bool:
        """Return True if cluster matches the filter."""
        ...


class SimpleFilter:
    """Simple filter implementation using AST evaluation."""

    def __init__(self, query: str, ast: ASTNode):
        self.query = query
        self.ast = ast

    def matches(self, cluster: Cluster) -> bool:
        """Evaluate the filter against a cluster."""
        try:
            return self.ast.evaluate(cluster)
        except FilterEvalError as e:
            raise FilterEvalError(f"Error evaluating filter '{self.query}': {e}")
