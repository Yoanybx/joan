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

/// Span-free, declaration-normalized AST used for semantic identity.
///
/// This representation is intentionally separate from [`Program`]: it freezes
/// identity semantics without making diagnostics or parser internals part of a
/// program digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalProgram {
    /// Canonical AST schema.
    pub schema: String,
    /// Module name.
    pub module: String,
    /// Functions sorted by name.
    pub functions: Vec<CanonicalFunction>,
}

impl CanonicalProgram {
    /// Exact schema identifier covered by the canonical digest.
    pub const SCHEMA: &'static str = "joan.canonical-ast.v0";
}

/// One canonical function declaration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalFunction {
    /// Function name.
    pub name: String,
    /// Ordered parameters.
    pub parameters: Vec<CanonicalParameter>,
    /// Declared return type.
    pub return_type: Type,
    /// Lexicographically sorted effect row.
    pub effects: Vec<String>,
    /// Ordered body statements.
    pub body: Vec<CanonicalStatement>,
}

/// One canonical function parameter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalParameter {
    /// Parameter name.
    pub name: String,
    /// Parameter type.
    pub value_type: Type,
}

/// One span-free canonical statement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "kebab-case")]
pub enum CanonicalStatement {
    /// Immutable local binding.
    Let {
        /// Local name.
        name: String,
        /// Declared type.
        value_type: Type,
        /// Initializer.
        value: CanonicalExpression,
    },
    /// Function return.
    Return {
        /// Optional value for `unit` functions.
        value: Option<CanonicalExpression>,
    },
    /// Host-effect request.
    Request {
        /// Declared effect name.
        effect: String,
        /// Ordered request arguments.
        arguments: Vec<CanonicalExpression>,
    },
    /// Expression statement.
    Expression {
        /// Expression.
        expression: CanonicalExpression,
    },
}

/// One span-free canonical expression.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "kebab-case")]
pub enum CanonicalExpression {
    /// Exact signed integer encoded as decimal text for lossless JCE1 transport.
    Integer {
        /// Canonical base-10 `i64` spelling.
        value: String,
    },
    /// Boolean literal.
    Boolean {
        /// Value.
        value: bool,
    },
    /// Decoded UTF-8 string literal.
    String {
        /// Value.
        value: String,
    },
    /// Local variable reference.
    Variable {
        /// Name.
        name: String,
    },
    /// Unary expression.
    Unary {
        /// Operator.
        operator: UnaryOperator,
        /// Operand.
        operand: Box<Self>,
    },
    /// Binary expression.
    Binary {
        /// Operator.
        operator: BinaryOperator,
        /// Left operand.
        left: Box<Self>,
        /// Right operand.
        right: Box<Self>,
    },
    /// Function call.
    Call {
        /// Function name.
        function: String,
        /// Ordered arguments.
        arguments: Vec<Self>,
    },
}

impl Program {
    /// Project this parsed AST into its canonical semantic representation.
    #[must_use]
    pub fn canonical(&self) -> CanonicalProgram {
        let mut functions = self
            .functions
            .iter()
            .map(CanonicalFunction::from)
            .collect::<Vec<_>>();
        functions.sort_by(|left, right| left.name.cmp(&right.name));
        CanonicalProgram {
            schema: CanonicalProgram::SCHEMA.to_owned(),
            module: self.module.clone(),
            functions,
        }
    }
}

impl From<&Function> for CanonicalFunction {
    fn from(function: &Function) -> Self {
        let mut effects = function.effects.clone();
        effects.sort();
        Self {
            name: function.name.clone(),
            parameters: function
                .parameters
                .iter()
                .map(CanonicalParameter::from)
                .collect(),
            return_type: function.return_type.clone(),
            effects,
            body: function.body.iter().map(CanonicalStatement::from).collect(),
        }
    }
}

impl From<&Parameter> for CanonicalParameter {
    fn from(parameter: &Parameter) -> Self {
        Self {
            name: parameter.name.clone(),
            value_type: parameter.value_type.clone(),
        }
    }
}

impl From<&Statement> for CanonicalStatement {
    fn from(statement: &Statement) -> Self {
        match statement {
            Statement::Let {
                name,
                value_type,
                value,
                ..
            } => Self::Let {
                name: name.clone(),
                value_type: value_type.clone(),
                value: CanonicalExpression::from(value),
            },
            Statement::Return { value, .. } => Self::Return {
                value: value.as_ref().map(CanonicalExpression::from),
            },
            Statement::Request {
                effect, arguments, ..
            } => Self::Request {
                effect: effect.clone(),
                arguments: arguments.iter().map(CanonicalExpression::from).collect(),
            },
            Statement::Expression { expression, .. } => Self::Expression {
                expression: CanonicalExpression::from(expression),
            },
        }
    }
}

impl From<&Expression> for CanonicalExpression {
    fn from(expression: &Expression) -> Self {
        match expression {
            Expression::Integer { value, .. } => Self::Integer {
                value: value.to_string(),
            },
            Expression::Boolean { value, .. } => Self::Boolean { value: *value },
            Expression::String { value, .. } => Self::String {
                value: value.clone(),
            },
            Expression::Variable { name, .. } => Self::Variable { name: name.clone() },
            Expression::Unary {
                operator, operand, ..
            } => Self::Unary {
                operator: operator.clone(),
                operand: Box::new(Self::from(operand.as_ref())),
            },
            Expression::Binary {
                operator,
                left,
                right,
                ..
            } => Self::Binary {
                operator: operator.clone(),
                left: Box::new(Self::from(left.as_ref())),
                right: Box::new(Self::from(right.as_ref())),
            },
            Expression::Call {
                function,
                arguments,
                ..
            } => Self::Call {
                function: function.clone(),
                arguments: arguments.iter().map(Self::from).collect(),
            },
        }
    }
}
