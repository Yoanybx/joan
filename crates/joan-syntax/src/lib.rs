//! Bounded lexer, parser, and canonical formatter for JOAN source v0.

use joan_ast::{
    BinaryOperator, Diagnostic, DiagnosticReport, Expression, Function, Parameter, Position,
    Program, Span, Statement, Type, UnaryOperator,
};
use std::fmt::Write as _;

const MAX_SOURCE_BYTES: usize = 1_048_576;
const MAX_TOKENS: usize = 200_000;

#[derive(Clone, Debug, PartialEq, Eq)]
enum TokenKind {
    Module,
    Fn,
    Effects,
    Let,
    Return,
    Request,
    True,
    False,
    I64,
    Bool,
    StringType,
    Unit,
    Identifier(String),
    Integer(i64),
    String(String),
    LeftParen,
    RightParen,
    LeftBrace,
    RightBrace,
    LeftBracket,
    RightBracket,
    Comma,
    Colon,
    Semicolon,
    Arrow,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Equal,
    EqualEqual,
    Bang,
    BangEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    AndAnd,
    OrOr,
    Eof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Token {
    kind: TokenKind,
    span: Span,
}

struct Lexer<'a> {
    source: &'a str,
    offset: usize,
    line: usize,
    column: usize,
    tokens: Vec<Token>,
}

impl<'a> Lexer<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            offset: 0,
            line: 1,
            column: 1,
            tokens: Vec::new(),
        }
    }

    fn position(&self) -> Position {
        Position {
            offset: self.offset,
            line: self.line,
            column: self.column,
        }
    }

    fn current(&self) -> Option<char> {
        self.source.get(self.offset..)?.chars().next()
    }

    fn next(&self) -> Option<char> {
        let mut chars = self.source.get(self.offset..)?.chars();
        chars.next()?;
        chars.next()
    }

    fn bump(&mut self) -> Option<char> {
        let value = self.current()?;
        self.offset += value.len_utf8();
        if value == '\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        Some(value)
    }

    fn push(&mut self, kind: TokenKind, start: Position) -> Result<(), Diagnostic> {
        if self.tokens.len() >= MAX_TOKENS {
            return Err(Diagnostic::error(
                "J0003",
                "token limit exceeded",
                Span {
                    start,
                    end: self.position(),
                },
            ));
        }
        self.tokens.push(Token {
            kind,
            span: Span {
                start,
                end: self.position(),
            },
        });
        Ok(())
    }

    fn lex(mut self) -> Result<Vec<Token>, DiagnosticReport> {
        if self.source.len() > MAX_SOURCE_BYTES {
            return Err(DiagnosticReport::rejected(
                "lex",
                vec![Diagnostic::error(
                    "J0001",
                    format!("source exceeds {MAX_SOURCE_BYTES} UTF-8 bytes"),
                    Span::default(),
                )],
            ));
        }
        while let Some(value) = self.current() {
            let start = self.position();
            let result = if value.is_whitespace() {
                self.bump();
                Ok(())
            } else if value == '/' && self.next() == Some('/') {
                self.bump();
                self.bump();
                while self.current().is_some_and(|ch| ch != '\n') {
                    self.bump();
                }
                Ok(())
            } else if value.is_ascii_alphabetic() || value == '_' {
                self.identifier(start)
            } else if value.is_ascii_digit() {
                self.integer(start)
            } else if value == '"' {
                self.string(start)
            } else {
                self.symbol(start, value)
            };
            if let Err(error) = result {
                return Err(DiagnosticReport::rejected("lex", vec![error]));
            }
        }
        let position = self.position();
        self.tokens.push(Token {
            kind: TokenKind::Eof,
            span: Span {
                start: position,
                end: position,
            },
        });
        Ok(self.tokens)
    }

    fn identifier(&mut self, start: Position) -> Result<(), Diagnostic> {
        while self
            .current()
            .is_some_and(|value| value.is_ascii_alphanumeric() || value == '_')
        {
            self.bump();
        }
        let Some(text) = self.source.get(start.offset..self.offset) else {
            return Err(Diagnostic::error(
                "J0002",
                "invalid identifier span",
                Span::default(),
            ));
        };
        let kind = match text {
            "module" => TokenKind::Module,
            "fn" => TokenKind::Fn,
            "effects" => TokenKind::Effects,
            "let" => TokenKind::Let,
            "return" => TokenKind::Return,
            "request" => TokenKind::Request,
            "true" => TokenKind::True,
            "false" => TokenKind::False,
            "i64" => TokenKind::I64,
            "bool" => TokenKind::Bool,
            "string" => TokenKind::StringType,
            "unit" => TokenKind::Unit,
            _ => TokenKind::Identifier(text.to_owned()),
        };
        self.push(kind, start)
    }

    fn integer(&mut self, start: Position) -> Result<(), Diagnostic> {
        while self.current().is_some_and(|value| value.is_ascii_digit()) {
            self.bump();
        }
        let Some(text) = self.source.get(start.offset..self.offset) else {
            return Err(Diagnostic::error(
                "J0004",
                "invalid integer span",
                Span::default(),
            ));
        };
        let value = text.parse::<i64>().map_err(|_| {
            Diagnostic::error(
                "J0005",
                "integer literal is outside the i64 range",
                Span {
                    start,
                    end: self.position(),
                },
            )
        })?;
        self.push(TokenKind::Integer(value), start)
    }

    fn string(&mut self, start: Position) -> Result<(), Diagnostic> {
        self.bump();
        let mut decoded = String::new();
        loop {
            let Some(value) = self.current() else {
                return Err(Diagnostic::error(
                    "J0006",
                    "unterminated string literal",
                    Span {
                        start,
                        end: self.position(),
                    },
                ));
            };
            if value == '"' {
                self.bump();
                break;
            }
            if value == '\n' || value == '\r' {
                return Err(Diagnostic::error(
                    "J0007",
                    "string literals cannot contain raw newlines",
                    Span {
                        start,
                        end: self.position(),
                    },
                ));
            }
            if value == '\\' {
                self.bump();
                let Some(escaped) = self.bump() else {
                    return Err(Diagnostic::error(
                        "J0008",
                        "unterminated string escape",
                        Span {
                            start,
                            end: self.position(),
                        },
                    ));
                };
                decoded.push(match escaped {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    '\\' => '\\',
                    '"' => '"',
                    _ => {
                        return Err(Diagnostic::error(
                            "J0009",
                            format!("unsupported string escape: \\{escaped}"),
                            Span {
                                start,
                                end: self.position(),
                            },
                        ));
                    }
                });
            } else if value.is_control() {
                return Err(Diagnostic::error(
                    "J0010",
                    "control character must be escaped",
                    Span {
                        start,
                        end: self.position(),
                    },
                ));
            } else {
                decoded.push(value);
                self.bump();
            }
        }
        self.push(TokenKind::String(decoded), start)
    }

    fn symbol(&mut self, start: Position, value: char) -> Result<(), Diagnostic> {
        self.bump();
        let kind = match (value, self.current()) {
            ('-', Some('>')) => {
                self.bump();
                TokenKind::Arrow
            }
            ('=', Some('=')) => {
                self.bump();
                TokenKind::EqualEqual
            }
            ('!', Some('=')) => {
                self.bump();
                TokenKind::BangEqual
            }
            ('<', Some('=')) => {
                self.bump();
                TokenKind::LessEqual
            }
            ('>', Some('=')) => {
                self.bump();
                TokenKind::GreaterEqual
            }
            ('&', Some('&')) => {
                self.bump();
                TokenKind::AndAnd
            }
            ('|', Some('|')) => {
                self.bump();
                TokenKind::OrOr
            }
            ('(', _) => TokenKind::LeftParen,
            (')', _) => TokenKind::RightParen,
            ('{', _) => TokenKind::LeftBrace,
            ('}', _) => TokenKind::RightBrace,
            ('[', _) => TokenKind::LeftBracket,
            (']', _) => TokenKind::RightBracket,
            (',', _) => TokenKind::Comma,
            (':', _) => TokenKind::Colon,
            (';', _) => TokenKind::Semicolon,
            ('+', _) => TokenKind::Plus,
            ('-', _) => TokenKind::Minus,
            ('*', _) => TokenKind::Star,
            ('/', _) => TokenKind::Slash,
            ('%', _) => TokenKind::Percent,
            ('=', _) => TokenKind::Equal,
            ('!', _) => TokenKind::Bang,
            ('<', _) => TokenKind::Less,
            ('>', _) => TokenKind::Greater,
            _ => {
                return Err(Diagnostic::error(
                    "J0011",
                    format!("unexpected character: {value}"),
                    Span {
                        start,
                        end: self.position(),
                    },
                ));
            }
        };
        self.push(kind, start)
    }
}

struct Parser {
    tokens: Vec<Token>,
    cursor: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, cursor: 0 }
    }

    fn current(&self) -> &Token {
        &self.tokens[self.cursor]
    }

    fn advance(&mut self) -> Token {
        let token = self.tokens[self.cursor].clone();
        if !matches!(token.kind, TokenKind::Eof) {
            self.cursor += 1;
        }
        token
    }

    fn is(&self, kind: &TokenKind) -> bool {
        std::mem::discriminant(&self.current().kind) == std::mem::discriminant(kind)
    }

    fn consume(&mut self, kind: &TokenKind) -> Option<Token> {
        self.is(kind).then(|| self.advance())
    }

    fn expect(
        &mut self,
        kind: &TokenKind,
        code: &'static str,
        message: &'static str,
    ) -> Result<Token, Diagnostic> {
        if self.is(kind) {
            Ok(self.advance())
        } else {
            Err(Diagnostic::error(code, message, self.current().span))
        }
    }

    fn identifier(
        &mut self,
        code: &'static str,
        message: &'static str,
    ) -> Result<(String, Span), Diagnostic> {
        let token = self.advance();
        if let TokenKind::Identifier(value) = token.kind {
            Ok((value, token.span))
        } else {
            Err(Diagnostic::error(code, message, token.span))
        }
    }

    fn parse(mut self) -> Result<Program, DiagnosticReport> {
        self.parse_program()
            .map_err(|error| DiagnosticReport::rejected("parse", vec![error]))
    }

    fn parse_program(&mut self) -> Result<Program, Diagnostic> {
        let start = self
            .expect(
                &TokenKind::Module,
                "J1001",
                "source must start with `module`",
            )?
            .span;
        let (module, _) = self.identifier("J1002", "expected module name")?;
        self.expect(
            &TokenKind::Semicolon,
            "J1003",
            "expected `;` after module name",
        )?;
        let mut functions = Vec::new();
        while !self.is(&TokenKind::Eof) {
            functions.push(self.function()?);
        }
        if functions.is_empty() {
            return Err(Diagnostic::error(
                "J1004",
                "module must declare at least one function",
                self.current().span,
            ));
        }
        Ok(Program {
            schema: "joan.ast.v0".to_owned(),
            module,
            functions,
            span: start.join(self.current().span),
        })
    }

    fn function(&mut self) -> Result<Function, Diagnostic> {
        let start = self.expect(&TokenKind::Fn, "J1010", "expected `fn`")?.span;
        let (name, _) = self.identifier("J1011", "expected function name")?;
        self.expect(
            &TokenKind::LeftParen,
            "J1012",
            "expected `(` after function name",
        )?;
        let mut parameters = Vec::new();
        if !self.is(&TokenKind::RightParen) {
            loop {
                let (parameter_name, parameter_span) =
                    self.identifier("J1013", "expected parameter name")?;
                self.expect(
                    &TokenKind::Colon,
                    "J1014",
                    "expected `:` after parameter name",
                )?;
                let (value_type, type_span) = self.value_type()?;
                parameters.push(Parameter {
                    name: parameter_name,
                    value_type,
                    span: parameter_span.join(type_span),
                });
                if self.consume(&TokenKind::Comma).is_none() {
                    break;
                }
            }
        }
        self.expect(
            &TokenKind::RightParen,
            "J1015",
            "expected `)` after parameters",
        )?;
        self.expect(
            &TokenKind::Arrow,
            "J1016",
            "expected `->` before return type",
        )?;
        let (return_type, _) = self.value_type()?;
        self.expect(
            &TokenKind::Effects,
            "J1017",
            "every function must declare `effects [...]`",
        )?;
        self.expect(
            &TokenKind::LeftBracket,
            "J1018",
            "expected `[` after `effects`",
        )?;
        let mut effects = Vec::new();
        if !self.is(&TokenKind::RightBracket) {
            loop {
                effects.push(self.identifier("J1019", "expected effect name")?.0);
                if self.consume(&TokenKind::Comma).is_none() {
                    break;
                }
            }
        }
        self.expect(
            &TokenKind::RightBracket,
            "J1020",
            "expected `]` after effect row",
        )?;
        let (body, body_span) = self.block()?;
        Ok(Function {
            name,
            parameters,
            return_type,
            effects,
            body,
            span: start.join(body_span),
        })
    }

    fn value_type(&mut self) -> Result<(Type, Span), Diagnostic> {
        let token = self.advance();
        let value_type = match token.kind {
            TokenKind::I64 => Type::I64,
            TokenKind::Bool => Type::Bool,
            TokenKind::StringType => Type::String,
            TokenKind::Unit => Type::Unit,
            _ => {
                return Err(Diagnostic::error(
                    "J1021",
                    "expected type: i64, bool, string, or unit",
                    token.span,
                ));
            }
        };
        Ok((value_type, token.span))
    }

    fn block(&mut self) -> Result<(Vec<Statement>, Span), Diagnostic> {
        let start = self
            .expect(&TokenKind::LeftBrace, "J1030", "expected `{`")?
            .span;
        let mut statements = Vec::new();
        while !self.is(&TokenKind::RightBrace) {
            if self.is(&TokenKind::Eof) {
                return Err(Diagnostic::error(
                    "J1031",
                    "unterminated function body",
                    start,
                ));
            }
            statements.push(self.statement()?);
        }
        let end = self.advance().span;
        Ok((statements, start.join(end)))
    }

    fn statement(&mut self) -> Result<Statement, Diagnostic> {
        if self.is(&TokenKind::Let) {
            return self.let_statement();
        }
        if self.is(&TokenKind::Return) {
            return self.return_statement();
        }
        if self.is(&TokenKind::Request) {
            return self.request_statement();
        }
        let expression = self.expression()?;
        let span = expression.span().join(
            self.expect(
                &TokenKind::Semicolon,
                "J1040",
                "expected `;` after expression",
            )?
            .span,
        );
        Ok(Statement::Expression { expression, span })
    }

    fn let_statement(&mut self) -> Result<Statement, Diagnostic> {
        let start = self.advance().span;
        let (name, _) = self.identifier("J1041", "expected local name")?;
        self.expect(&TokenKind::Colon, "J1042", "expected `:` after local name")?;
        let (value_type, _) = self.value_type()?;
        self.expect(
            &TokenKind::Equal,
            "J1043",
            "expected `=` before initializer",
        )?;
        let value = self.expression()?;
        let end = self
            .expect(
                &TokenKind::Semicolon,
                "J1044",
                "expected `;` after local binding",
            )?
            .span;
        Ok(Statement::Let {
            name,
            value_type,
            value,
            span: start.join(end),
        })
    }

    fn return_statement(&mut self) -> Result<Statement, Diagnostic> {
        let start = self.advance().span;
        let value = if self.is(&TokenKind::Semicolon) {
            None
        } else {
            Some(self.expression()?)
        };
        let end = self
            .expect(&TokenKind::Semicolon, "J1045", "expected `;` after return")?
            .span;
        Ok(Statement::Return {
            value,
            span: start.join(end),
        })
    }

    fn request_statement(&mut self) -> Result<Statement, Diagnostic> {
        let start = self.advance().span;
        let (effect, _) = self.identifier("J1046", "expected requested effect name")?;
        let (arguments, call_span) = self.arguments()?;
        let end = self
            .expect(
                &TokenKind::Semicolon,
                "J1047",
                "expected `;` after effect request",
            )?
            .span;
        Ok(Statement::Request {
            effect,
            arguments,
            span: start.join(call_span).join(end),
        })
    }

    fn expression(&mut self) -> Result<Expression, Diagnostic> {
        self.or()
    }

    fn or(&mut self) -> Result<Expression, Diagnostic> {
        let mut expression = self.and()?;
        while self.consume(&TokenKind::OrOr).is_some() {
            let right = self.and()?;
            let span = expression.span().join(right.span());
            expression = Expression::Binary {
                operator: BinaryOperator::Or,
                left: Box::new(expression),
                right: Box::new(right),
                span,
            };
        }
        Ok(expression)
    }

    fn and(&mut self) -> Result<Expression, Diagnostic> {
        let mut expression = self.equality()?;
        while self.consume(&TokenKind::AndAnd).is_some() {
            let right = self.equality()?;
            let span = expression.span().join(right.span());
            expression = Expression::Binary {
                operator: BinaryOperator::And,
                left: Box::new(expression),
                right: Box::new(right),
                span,
            };
        }
        Ok(expression)
    }

    fn equality(&mut self) -> Result<Expression, Diagnostic> {
        let mut expression = self.comparison()?;
        loop {
            let operator = if self.consume(&TokenKind::EqualEqual).is_some() {
                Some(BinaryOperator::Equal)
            } else if self.consume(&TokenKind::BangEqual).is_some() {
                Some(BinaryOperator::NotEqual)
            } else {
                None
            };
            let Some(operator) = operator else { break };
            let right = self.comparison()?;
            let span = expression.span().join(right.span());
            expression = Expression::Binary {
                operator,
                left: Box::new(expression),
                right: Box::new(right),
                span,
            };
        }
        Ok(expression)
    }

    fn comparison(&mut self) -> Result<Expression, Diagnostic> {
        let mut expression = self.term()?;
        loop {
            let operator = if self.consume(&TokenKind::Less).is_some() {
                Some(BinaryOperator::Less)
            } else if self.consume(&TokenKind::LessEqual).is_some() {
                Some(BinaryOperator::LessEqual)
            } else if self.consume(&TokenKind::Greater).is_some() {
                Some(BinaryOperator::Greater)
            } else if self.consume(&TokenKind::GreaterEqual).is_some() {
                Some(BinaryOperator::GreaterEqual)
            } else {
                None
            };
            let Some(operator) = operator else { break };
            let right = self.term()?;
            let span = expression.span().join(right.span());
            expression = Expression::Binary {
                operator,
                left: Box::new(expression),
                right: Box::new(right),
                span,
            };
        }
        Ok(expression)
    }

    fn term(&mut self) -> Result<Expression, Diagnostic> {
        let mut expression = self.factor()?;
        loop {
            let operator = if self.consume(&TokenKind::Plus).is_some() {
                Some(BinaryOperator::Add)
            } else if self.consume(&TokenKind::Minus).is_some() {
                Some(BinaryOperator::Subtract)
            } else {
                None
            };
            let Some(operator) = operator else { break };
            let right = self.factor()?;
            let span = expression.span().join(right.span());
            expression = Expression::Binary {
                operator,
                left: Box::new(expression),
                right: Box::new(right),
                span,
            };
        }
        Ok(expression)
    }

    fn factor(&mut self) -> Result<Expression, Diagnostic> {
        let mut expression = self.unary()?;
        loop {
            let operator = if self.consume(&TokenKind::Star).is_some() {
                Some(BinaryOperator::Multiply)
            } else if self.consume(&TokenKind::Slash).is_some() {
                Some(BinaryOperator::Divide)
            } else if self.consume(&TokenKind::Percent).is_some() {
                Some(BinaryOperator::Remainder)
            } else {
                None
            };
            let Some(operator) = operator else { break };
            let right = self.unary()?;
            let span = expression.span().join(right.span());
            expression = Expression::Binary {
                operator,
                left: Box::new(expression),
                right: Box::new(right),
                span,
            };
        }
        Ok(expression)
    }

    fn unary(&mut self) -> Result<Expression, Diagnostic> {
        let operator = if let Some(token) = self.consume(&TokenKind::Minus) {
            Some((UnaryOperator::Negate, token.span))
        } else {
            self.consume(&TokenKind::Bang)
                .map(|token| (UnaryOperator::Not, token.span))
        };
        if let Some((operator, start)) = operator {
            let operand = self.unary()?;
            let span = start.join(operand.span());
            Ok(Expression::Unary {
                operator,
                operand: Box::new(operand),
                span,
            })
        } else {
            self.primary()
        }
    }

    fn primary(&mut self) -> Result<Expression, Diagnostic> {
        let token = self.advance();
        match token.kind {
            TokenKind::Integer(value) => Ok(Expression::Integer {
                value,
                span: token.span,
            }),
            TokenKind::True => Ok(Expression::Boolean {
                value: true,
                span: token.span,
            }),
            TokenKind::False => Ok(Expression::Boolean {
                value: false,
                span: token.span,
            }),
            TokenKind::String(value) => Ok(Expression::String {
                value,
                span: token.span,
            }),
            TokenKind::Identifier(name) => {
                if self.is(&TokenKind::LeftParen) {
                    let (arguments, end) = self.arguments()?;
                    Ok(Expression::Call {
                        function: name,
                        arguments,
                        span: token.span.join(end),
                    })
                } else {
                    Ok(Expression::Variable {
                        name,
                        span: token.span,
                    })
                }
            }
            TokenKind::LeftParen => {
                let expression = self.expression()?;
                self.expect(
                    &TokenKind::RightParen,
                    "J1050",
                    "expected `)` after expression",
                )?;
                Ok(expression)
            }
            _ => Err(Diagnostic::error(
                "J1051",
                "expected expression",
                token.span,
            )),
        }
    }

    fn arguments(&mut self) -> Result<(Vec<Expression>, Span), Diagnostic> {
        let start = self
            .expect(
                &TokenKind::LeftParen,
                "J1060",
                "expected `(` before arguments",
            )?
            .span;
        let mut arguments = Vec::new();
        if !self.is(&TokenKind::RightParen) {
            loop {
                arguments.push(self.expression()?);
                if self.consume(&TokenKind::Comma).is_none() {
                    break;
                }
            }
        }
        let end = self
            .expect(
                &TokenKind::RightParen,
                "J1061",
                "expected `)` after arguments",
            )?
            .span;
        Ok((arguments, start.join(end)))
    }
}

/// Parse one bounded JOAN v0 source module.
pub fn parse(source: &str) -> Result<Program, DiagnosticReport> {
    Parser::new(Lexer::new(source).lex()?).parse()
}

/// Parse and format one source module into canonical JOAN text.
pub fn format_source(source: &str) -> Result<String, DiagnosticReport> {
    Ok(format_program(&parse(source)?))
}

/// Format a parsed program deterministically.
#[must_use]
pub fn format_program(program: &Program) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "module {};", program.module);
    for function in &program.functions {
        output.push('\n');
        format_function(&mut output, function);
    }
    output
}

fn format_function(output: &mut String, function: &Function) {
    let _ = write!(output, "fn {}(", function.name);
    for (index, parameter) in function.parameters.iter().enumerate() {
        if index > 0 {
            output.push_str(", ");
        }
        let _ = write!(
            output,
            "{}: {}",
            parameter.name,
            parameter.value_type.as_str()
        );
    }
    let _ = write!(output, ") -> {} effects [", function.return_type.as_str());
    for (index, effect) in function.effects.iter().enumerate() {
        if index > 0 {
            output.push_str(", ");
        }
        output.push_str(effect);
    }
    output.push_str("] {\n");
    for statement in &function.body {
        output.push_str("  ");
        format_statement(output, statement);
        output.push('\n');
    }
    output.push_str("}\n");
}

fn format_statement(output: &mut String, statement: &Statement) {
    match statement {
        Statement::Let {
            name,
            value_type,
            value,
            ..
        } => {
            let _ = write!(output, "let {name}: {} = ", value_type.as_str());
            format_expression(output, value, 0);
            output.push(';');
        }
        Statement::Return { value, .. } => {
            output.push_str("return");
            if let Some(value) = value {
                output.push(' ');
                format_expression(output, value, 0);
            }
            output.push(';');
        }
        Statement::Request {
            effect, arguments, ..
        } => {
            let _ = write!(output, "request {effect}(");
            format_arguments(output, arguments);
            output.push_str(");");
        }
        Statement::Expression { expression, .. } => {
            format_expression(output, expression, 0);
            output.push(';');
        }
    }
}

fn format_arguments(output: &mut String, arguments: &[Expression]) {
    for (index, argument) in arguments.iter().enumerate() {
        if index > 0 {
            output.push_str(", ");
        }
        format_expression(output, argument, 0);
    }
}

fn precedence(expression: &Expression) -> u8 {
    match expression {
        Expression::Binary { operator, .. } => match operator {
            BinaryOperator::Or => 1,
            BinaryOperator::And => 2,
            BinaryOperator::Equal | BinaryOperator::NotEqual => 3,
            BinaryOperator::Less
            | BinaryOperator::LessEqual
            | BinaryOperator::Greater
            | BinaryOperator::GreaterEqual => 4,
            BinaryOperator::Add | BinaryOperator::Subtract => 5,
            BinaryOperator::Multiply | BinaryOperator::Divide | BinaryOperator::Remainder => 6,
        },
        Expression::Unary { .. } => 7,
        _ => 8,
    }
}

fn format_expression(output: &mut String, expression: &Expression, parent_precedence: u8) {
    let own_precedence = precedence(expression);
    let parenthesize = own_precedence < parent_precedence;
    if parenthesize {
        output.push('(');
    }
    match expression {
        Expression::Integer { value, .. } => {
            let _ = write!(output, "{value}");
        }
        Expression::Boolean { value, .. } => output.push_str(if *value { "true" } else { "false" }),
        Expression::String { value, .. } => format_string(output, value),
        Expression::Variable { name, .. } => output.push_str(name),
        Expression::Unary {
            operator, operand, ..
        } => {
            output.push_str(match operator {
                UnaryOperator::Negate => "-",
                UnaryOperator::Not => "!",
            });
            format_expression(output, operand, own_precedence);
        }
        Expression::Binary {
            operator,
            left,
            right,
            ..
        } => {
            format_expression(output, left, own_precedence);
            output.push_str(match operator {
                BinaryOperator::Add => " + ",
                BinaryOperator::Subtract => " - ",
                BinaryOperator::Multiply => " * ",
                BinaryOperator::Divide => " / ",
                BinaryOperator::Remainder => " % ",
                BinaryOperator::Equal => " == ",
                BinaryOperator::NotEqual => " != ",
                BinaryOperator::Less => " < ",
                BinaryOperator::LessEqual => " <= ",
                BinaryOperator::Greater => " > ",
                BinaryOperator::GreaterEqual => " >= ",
                BinaryOperator::And => " && ",
                BinaryOperator::Or => " || ",
            });
            format_expression(output, right, own_precedence + 1);
        }
        Expression::Call {
            function,
            arguments,
            ..
        } => {
            let _ = write!(output, "{function}(");
            format_arguments(output, arguments);
            output.push(')');
        }
    }
    if parenthesize {
        output.push(')');
    }
}

fn format_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\\' => output.push_str("\\\\"),
            '"' => output.push_str("\\\""),
            _ => output.push(character),
        }
    }
    output.push('"');
}
