//! Stable abstract syntax and diagnostics for the JOAN language preview.

use serde::{Deserialize, Serialize};
use std::fmt;

/// One 1-based source position plus its 0-based UTF-8 byte offset.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Position {
    /// UTF-8 byte offset.
    pub offset: usize,
    /// One-based line.
    pub line: usize,
    /// One-based Unicode-scalar column.
    pub column: usize,
}

/// Half-open source span.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Span {
    /// Inclusive start.
    pub start: Position,
    /// Exclusive end.
    pub end: Position,
}

impl Span {
    /// Join two ordered spans.
    #[must_use]
    pub fn join(self, other: Self) -> Self {
        Self {
            start: self.start,
            end: other.end,
        }
    }
}

/// Stable diagnostic severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Compilation cannot continue.
    Error,
}

/// Machine-readable language diagnostic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    /// Stable diagnostic code.
    pub code: String,
    /// Severity.
    pub severity: Severity,
    /// Human-readable summary.
    pub message: String,
    /// Exact source span when known.
    pub span: Span,
    /// Additional bounded context.
    pub notes: Vec<String>,
}

impl Diagnostic {
    /// Construct an error diagnostic.
    #[must_use]
    pub fn error(code: impl Into<String>, message: impl Into<String>, span: Span) -> Self {
        Self {
            code: code.into(),
            severity: Severity::Error,
            message: message.into(),
            span,
            notes: Vec::new(),
        }
    }

    /// Add one note.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }
}

/// Stable report returned for rejected source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticReport {
    /// Report schema.
    pub schema: String,
    /// Compile phase such as `parse` or `check`.
    pub phase: String,
    /// Always `rejected` for this report type.
    pub status: String,
    /// Ordered diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

impl DiagnosticReport {
    /// Build a deterministic rejected report.
    #[must_use]
    pub fn rejected(phase: impl Into<String>, diagnostics: Vec<Diagnostic>) -> Self {
        Self {
            schema: "joan.diagnostic-report.v0".to_owned(),
            phase: phase.into(),
            status: "rejected".to_owned(),
            diagnostics,
        }
    }
}

impl fmt::Display for DiagnosticReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(first) = self.diagnostics.first() {
            write!(
                formatter,
                "{} rejected with {}: {}",
                self.phase, first.code, first.message
            )
        } else {
            write!(formatter, "{} rejected without diagnostics", self.phase)
        }
    }
}

impl std::error::Error for DiagnosticReport {}

/// JOAN primitive type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Type {
    /// Signed 64-bit integer.
    I64,
    /// Boolean.
    Bool,
    /// UTF-8 string.
    String,
    /// Unit value.
    Unit,
}

impl Type {
    /// Canonical source spelling.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::I64 => "i64",
            Self::Bool => "bool",
            Self::String => "string",
            Self::Unit => "unit",
        }
    }
}

/// Unary operator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnaryOperator {
    /// Arithmetic negation.
    Negate,
    /// Boolean negation.
    Not,
}

/// Binary operator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BinaryOperator {
    /// Integer addition.
    Add,
    /// Integer subtraction.
    Subtract,
    /// Integer multiplication.
    Multiply,
    /// Integer division.
    Divide,
    /// Integer remainder.
    Remainder,
    /// Equality.
    Equal,
    /// Inequality.
    NotEqual,
    /// Less than.
    Less,
    /// Less than or equal.
    LessEqual,
    /// Greater than.
    Greater,
    /// Greater than or equal.
    GreaterEqual,
    /// Boolean conjunction.
    And,
    /// Boolean disjunction.
    Or,
}

/// Expression node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Expression {
    /// Integer literal.
    Integer {
        /// Value.
        value: i64,
        /// Source span excluded from semantic serialization.
        #[serde(skip, default)]
        span: Span,
    },
    /// Boolean literal.
    Boolean {
        /// Value.
        value: bool,
        /// Source span.
        #[serde(skip, default)]
        span: Span,
    },
    /// String literal after escape decoding.
    String {
        /// Value.
        value: String,
        /// Source span.
        #[serde(skip, default)]
        span: Span,
    },
    /// Local variable reference.
    Variable {
        /// Name.
        name: String,
        /// Source span.
        #[serde(skip, default)]
        span: Span,
    },
    /// Unary expression.
    Unary {
        /// Operator.
        operator: UnaryOperator,
        /// Operand.
        operand: Box<Self>,
        /// Source span.
        #[serde(skip, default)]
        span: Span,
    },
    /// Binary expression.
    Binary {
        /// Operator.
        operator: BinaryOperator,
        /// Left operand.
        left: Box<Self>,
        /// Right operand.
        right: Box<Self>,
        /// Source span.
        #[serde(skip, default)]
        span: Span,
    },
    /// Function call.
    Call {
        /// Function name.
        function: String,
        /// Arguments.
        arguments: Vec<Self>,
        /// Source span.
        #[serde(skip, default)]
        span: Span,
    },
}

impl Expression {
    /// Source span.
    #[must_use]
    pub const fn span(&self) -> Span {
        match self {
            Self::Integer { span, .. }
            | Self::Boolean { span, .. }
            | Self::String { span, .. }
            | Self::Variable { span, .. }
            | Self::Unary { span, .. }
            | Self::Binary { span, .. }
            | Self::Call { span, .. } => *span,
        }
    }
}

/// Statement node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Statement {
    /// Immutable local binding.
    Let {
        /// Local name.
        name: String,
        /// Declared type.
        value_type: Type,
        /// Initializer.
        value: Expression,
        /// Source span.
        #[serde(skip, default)]
        span: Span,
    },
    /// Function return.
    Return {
        /// Optional value for `unit` functions.
        value: Option<Expression>,
        /// Source span.
        #[serde(skip, default)]
        span: Span,
    },
    /// A host-effect request that is recorded but never executed by the preview VM.
    Request {
        /// Declared effect name.
        effect: String,
        /// Request arguments.
        arguments: Vec<Expression>,
        /// Source span.
        #[serde(skip, default)]
        span: Span,
    },
    /// Expression evaluated only for its value-independent checks.
    Expression {
        /// Expression.
        expression: Expression,
        /// Source span.
        #[serde(skip, default)]
        span: Span,
    },
}

impl Statement {
    /// Source span.
    #[must_use]
    pub const fn span(&self) -> Span {
        match self {
            Self::Let { span, .. }
            | Self::Return { span, .. }
            | Self::Request { span, .. }
            | Self::Expression { span, .. } => *span,
        }
    }
}

/// Function parameter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Parameter {
    /// Parameter name.
    pub name: String,
    /// Parameter type.
    pub value_type: Type,
    /// Source span.
    #[serde(skip, default)]
    pub span: Span,
}

/// Function declaration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Function {
    /// Function name.
    pub name: String,
    /// Ordered parameters.
    pub parameters: Vec<Parameter>,
    /// Return type.
    pub return_type: Type,
    /// Explicit effect row.
    pub effects: Vec<String>,
    /// Ordered body statements.
    pub body: Vec<Statement>,
    /// Source span.
    #[serde(skip, default)]
    pub span: Span,
}

/// Complete JOAN source module.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Program {
    /// AST schema.
    pub schema: String,
    /// Module name.
    pub module: String,
    /// Function declarations in source order.
    pub functions: Vec<Function>,
    /// Source span.
    #[serde(skip, default)]
    pub span: Span,
}
