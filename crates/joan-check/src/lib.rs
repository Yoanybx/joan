//! Static type, effect-row, and bounded-termination checks for JOAN v0.

use joan_ast::{
    BinaryOperator, Diagnostic, DiagnosticReport, Expression, Function, Program, Span, Statement,
    Type, UnaryOperator,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};

const MAX_FUNCTIONS: usize = 1_024;
const MAX_PARAMETERS: usize = 64;
const MAX_STATEMENTS: usize = 100_000;

#[derive(Clone)]
struct FunctionSignature {
    parameters: Vec<Type>,
    return_type: Type,
    effects: BTreeSet<String>,
    span: Span,
}

struct RequestCheckContext<'a> {
    locals: &'a HashMap<String, Type>,
    authority_slots: &'a HashMap<String, String>,
    available_authorities: &'a mut BTreeSet<String>,
    function: &'a Function,
}

/// Successful static-check receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckReceipt {
    /// Receipt schema.
    pub schema: String,
    /// Always `accepted`.
    pub status: String,
    /// Module name.
    pub module: String,
    /// Number of functions.
    pub function_count: usize,
    /// Number of statements.
    pub statement_count: usize,
    /// Distinct declared effect names.
    pub declared_effects: Vec<String>,
    /// Why every accepted program terminates under v0 semantics.
    pub termination_profile: String,
    /// External effects are requests only.
    pub effect_profile: String,
    /// Static authority discipline applied to requests.
    pub authority_profile: String,
    /// Number of declared per-invocation authority slots.
    pub authority_slot_count: usize,
}

/// Validate types, names, effects, entrypoint, and the acyclic call graph.
pub fn check(program: &Program) -> Result<CheckReceipt, DiagnosticReport> {
    let mut checker = Checker::new(program);
    checker.run()?;
    let authority_profile = if checker.linear_profile {
        "linear-one-shot-per-invocation"
    } else {
        "legacy-receipt-only"
    };
    let authority_slot_count = program
        .functions
        .iter()
        .filter_map(|function| function.authorities.as_ref())
        .map(Vec::len)
        .sum();
    Ok(CheckReceipt {
        schema: "joan.check-receipt.v0".to_owned(),
        status: "accepted".to_owned(),
        module: program.module.clone(),
        function_count: program.functions.len(),
        statement_count: program
            .functions
            .iter()
            .map(|function| function.body.len())
            .sum(),
        declared_effects: checker.all_effects.into_iter().collect(),
        termination_profile: "no-loops-acyclic-call-graph-bounded-vm".to_owned(),
        effect_profile: "requests-recorded-never-executed".to_owned(),
        authority_profile: authority_profile.to_owned(),
        authority_slot_count,
    })
}

struct Checker<'a> {
    program: &'a Program,
    signatures: HashMap<String, FunctionSignature>,
    calls: HashMap<String, Vec<(String, Span)>>,
    all_effects: BTreeSet<String>,
    linear_profile: bool,
    diagnostics: Vec<Diagnostic>,
}

impl<'a> Checker<'a> {
    fn new(program: &'a Program) -> Self {
        let linear_profile = program.functions.iter().any(|function| {
            function.authorities.is_some()
                || function.body.iter().any(|statement| {
                    matches!(
                        statement,
                        Statement::Request {
                            authority: Some(_),
                            ..
                        }
                    )
                })
        });
        Self {
            program,
            signatures: HashMap::new(),
            calls: HashMap::new(),
            all_effects: BTreeSet::new(),
            linear_profile,
            diagnostics: Vec::new(),
        }
    }

    fn run(&mut self) -> Result<(), DiagnosticReport> {
        self.collect_signatures();
        self.check_entrypoint();
        self.check_bodies();
        self.check_acyclic_calls();
        if self.diagnostics.is_empty() {
            Ok(())
        } else {
            Err(DiagnosticReport::rejected(
                "check",
                std::mem::take(&mut self.diagnostics),
            ))
        }
    }

    fn collect_signatures(&mut self) {
        if self.program.functions.len() > MAX_FUNCTIONS {
            self.diagnostics.push(Diagnostic::error(
                "J2001",
                format!("function count exceeds {MAX_FUNCTIONS}"),
                self.program.span,
            ));
        }
        let mut statement_count = 0usize;
        for function in &self.program.functions {
            statement_count = statement_count.saturating_add(function.body.len());
            if function.parameters.len() > MAX_PARAMETERS {
                self.diagnostics.push(Diagnostic::error(
                    "J2002",
                    format!("function parameter count exceeds {MAX_PARAMETERS}"),
                    function.span,
                ));
            }
            let mut effects = BTreeSet::new();
            for effect in &function.effects {
                if !effects.insert(effect.clone()) {
                    self.diagnostics.push(Diagnostic::error(
                        "J2003",
                        format!("duplicate effect `{effect}`"),
                        function.span,
                    ));
                }
                self.all_effects.insert(effect.clone());
            }
            let signature = FunctionSignature {
                parameters: function
                    .parameters
                    .iter()
                    .map(|parameter| parameter.value_type.clone())
                    .collect(),
                return_type: function.return_type.clone(),
                effects,
                span: function.span,
            };
            if self
                .signatures
                .insert(function.name.clone(), signature)
                .is_some()
            {
                self.diagnostics.push(Diagnostic::error(
                    "J2004",
                    format!("duplicate function `{}`", function.name),
                    function.span,
                ));
            }
        }
        if statement_count > MAX_STATEMENTS {
            self.diagnostics.push(Diagnostic::error(
                "J2005",
                format!("statement count exceeds {MAX_STATEMENTS}"),
                self.program.span,
            ));
        }
    }

    fn check_entrypoint(&mut self) {
        let Some(main) = self.signatures.get("main") else {
            self.diagnostics.push(Diagnostic::error(
                "J2010",
                "module must declare `fn main()`",
                self.program.span,
            ));
            return;
        };
        if !main.parameters.is_empty() {
            self.diagnostics.push(Diagnostic::error(
                "J2011",
                "`main` cannot accept parameters in JOAN v0",
                main.span,
            ));
        }
    }

    fn check_bodies(&mut self) {
        for function in &self.program.functions {
            self.check_function(function);
        }
    }

    fn check_function(&mut self, function: &Function) {
        let mut locals = HashMap::new();
        let Some((authority_slots, mut available_authorities)) = self.authority_state(function)
        else {
            return;
        };
        for parameter in &function.parameters {
            if parameter.value_type == Type::Unit {
                self.diagnostics.push(Diagnostic::error(
                    "J2020",
                    "parameters cannot have type unit",
                    parameter.span,
                ));
            }
            if locals
                .insert(parameter.name.clone(), parameter.value_type.clone())
                .is_some()
            {
                self.diagnostics.push(Diagnostic::error(
                    "J2021",
                    format!("duplicate parameter `{}`", parameter.name),
                    parameter.span,
                ));
            }
        }
        if function.body.is_empty() {
            self.diagnostics.push(Diagnostic::error(
                "J2022",
                "function body cannot be empty",
                function.span,
            ));
            return;
        }
        let mut returned = false;
        for statement in &function.body {
            if returned {
                self.diagnostics.push(Diagnostic::error(
                    "J2023",
                    "unreachable statement after return",
                    statement.span(),
                ));
                continue;
            }
            returned = self.check_statement(
                statement,
                &mut locals,
                &authority_slots,
                &mut available_authorities,
                function,
            );
        }
        if !returned {
            self.diagnostics.push(Diagnostic::error(
                "J2029",
                "every function must end with an explicit return",
                function.span,
            ));
        }
        if self.linear_profile {
            for authority in available_authorities {
                self.diagnostics.push(
                    Diagnostic::error(
                        "J2057",
                        format!("authority slot `{authority}` was not consumed"),
                        function.span,
                    )
                    .with_note("linear authority slots must be moved exactly once"),
                );
            }
        }
    }

    fn authority_state(
        &mut self,
        function: &Function,
    ) -> Option<(HashMap<String, String>, BTreeSet<String>)> {
        let mut authority_slots = HashMap::new();
        let mut available_authorities = BTreeSet::new();
        if self.linear_profile {
            let Some(authorities) = &function.authorities else {
                self.diagnostics.push(
                    Diagnostic::error(
                        "J2050",
                        format!(
                            "function `{}` must declare `authorities [...]` in a linear module",
                            function.name
                        ),
                        function.span,
                    )
                    .with_note("authority profiles cannot be mixed inside one module"),
                );
                return None;
            };
            for authority in authorities {
                if authority_slots
                    .insert(authority.name.clone(), authority.effect.clone())
                    .is_some()
                {
                    self.diagnostics.push(Diagnostic::error(
                        "J2051",
                        format!("duplicate authority slot `{}`", authority.name),
                        authority.span,
                    ));
                }
                available_authorities.insert(authority.name.clone());
                if !function
                    .effects
                    .iter()
                    .any(|declared| declared == &authority.effect)
                {
                    self.diagnostics.push(
                        Diagnostic::error(
                            "J2052",
                            format!(
                                "authority slot `{}` names undeclared effect `{}`",
                                authority.name, authority.effect
                            ),
                            authority.span,
                        )
                        .with_note("authority cannot widen the function effect row"),
                    );
                }
            }
        }
        Some((authority_slots, available_authorities))
    }

    fn check_statement(
        &mut self,
        statement: &Statement,
        locals: &mut HashMap<String, Type>,
        authority_slots: &HashMap<String, String>,
        available_authorities: &mut BTreeSet<String>,
        function: &Function,
    ) -> bool {
        match statement {
            Statement::Let {
                name,
                value_type,
                value,
                span,
            } => {
                if *value_type == Type::Unit {
                    self.diagnostics.push(Diagnostic::error(
                        "J2024",
                        "local bindings cannot have type unit",
                        *span,
                    ));
                }
                let actual = self.expression_type(value, locals, function);
                self.require_type(value_type, actual.as_ref(), value.span(), "initializer");
                if locals.insert(name.clone(), value_type.clone()).is_some() {
                    self.diagnostics.push(Diagnostic::error(
                        "J2025",
                        format!("duplicate local `{name}`"),
                        *span,
                    ));
                }
                false
            }
            Statement::Return { value, span } => {
                match (value, &function.return_type) {
                    (None, Type::Unit) => {}
                    (None, expected) => self.diagnostics.push(Diagnostic::error(
                        "J2026",
                        format!("return requires a value of type {}", expected.as_str()),
                        *span,
                    )),
                    (Some(_), Type::Unit) => self.diagnostics.push(Diagnostic::error(
                        "J2027",
                        "unit function must use `return;`",
                        *span,
                    )),
                    (Some(expression), expected) => {
                        let actual = self.expression_type(expression, locals, function);
                        self.require_type(
                            expected,
                            actual.as_ref(),
                            expression.span(),
                            "return value",
                        );
                    }
                }
                true
            }
            Statement::Request {
                effect,
                authority,
                arguments,
                span,
            } => {
                let mut context = RequestCheckContext {
                    locals,
                    authority_slots,
                    available_authorities,
                    function,
                };
                self.check_request(effect, authority.as_deref(), arguments, *span, &mut context);
                false
            }
            Statement::Expression { expression, .. } => {
                self.expression_type(expression, locals, function);
                false
            }
        }
    }

    fn check_request(
        &mut self,
        effect: &str,
        authority: Option<&str>,
        arguments: &[Expression],
        span: Span,
        context: &mut RequestCheckContext<'_>,
    ) {
        if !context
            .function
            .effects
            .iter()
            .any(|declared| declared == effect)
        {
            self.diagnostics.push(
                Diagnostic::error(
                    "J2028",
                    format!("effect `{effect}` is not declared by this function"),
                    span,
                )
                .with_note("add the effect to `effects [...]` or remove the request"),
            );
        }
        for argument in arguments {
            self.expression_type(argument, context.locals, context.function);
        }
        if !self.linear_profile {
            return;
        }
        let Some(name) = authority else {
            self.diagnostics.push(
                Diagnostic::error(
                    "J2053",
                    format!("effect `{effect}` request has no linear authority slot"),
                    span,
                )
                .with_note("append `using <slot>` to move one declared authority"),
            );
            return;
        };
        let Some(allowed_effect) = context.authority_slots.get(name) else {
            self.diagnostics.push(Diagnostic::error(
                "J2054",
                format!("unknown authority slot `{name}`"),
                span,
            ));
            return;
        };
        if allowed_effect != effect {
            self.diagnostics.push(
                Diagnostic::error(
                    "J2055",
                    format!("authority slot `{name}` permits `{allowed_effect}`, not `{effect}`"),
                    span,
                )
                .with_note("authority slots are effect-specific and cannot widen"),
            );
            return;
        }
        if !context.available_authorities.remove(name) {
            self.diagnostics.push(
                Diagnostic::error(
                    "J2056",
                    format!("authority slot `{name}` was already consumed"),
                    span,
                )
                .with_note("one slot can authorize only one request per invocation"),
            );
        }
    }

    fn expression_type(
        &mut self,
        expression: &Expression,
        locals: &HashMap<String, Type>,
        caller: &Function,
    ) -> Option<Type> {
        match expression {
            Expression::Integer { .. } => Some(Type::I64),
            Expression::Boolean { .. } => Some(Type::Bool),
            Expression::String { .. } => Some(Type::String),
            Expression::Variable { name, span } => locals.get(name).cloned().or_else(|| {
                self.diagnostics.push(Diagnostic::error(
                    "J2030",
                    format!("unknown local `{name}`"),
                    *span,
                ));
                None
            }),
            Expression::Unary {
                operator,
                operand,
                span,
            } => {
                let actual = self.expression_type(operand, locals, caller);
                let expected = match operator {
                    UnaryOperator::Negate => Type::I64,
                    UnaryOperator::Not => Type::Bool,
                };
                self.require_type(&expected, actual.as_ref(), *span, "unary operand");
                Some(expected)
            }
            Expression::Binary {
                operator,
                left,
                right,
                span,
            } => Some(self.binary_type(operator, left, right, *span, locals, caller)),
            Expression::Call {
                function,
                arguments,
                span,
            } => self.call_type(function, arguments, *span, locals, caller),
        }
    }

    fn binary_type(
        &mut self,
        operator: &BinaryOperator,
        left: &Expression,
        right: &Expression,
        span: Span,
        locals: &HashMap<String, Type>,
        caller: &Function,
    ) -> Type {
        let left_type = self.expression_type(left, locals, caller);
        let right_type = self.expression_type(right, locals, caller);
        match operator {
            BinaryOperator::Add
            | BinaryOperator::Subtract
            | BinaryOperator::Multiply
            | BinaryOperator::Divide
            | BinaryOperator::Remainder => {
                self.require_type(&Type::I64, left_type.as_ref(), left.span(), "left operand");
                self.require_type(
                    &Type::I64,
                    right_type.as_ref(),
                    right.span(),
                    "right operand",
                );
                Type::I64
            }
            BinaryOperator::Less
            | BinaryOperator::LessEqual
            | BinaryOperator::Greater
            | BinaryOperator::GreaterEqual => {
                self.require_type(&Type::I64, left_type.as_ref(), left.span(), "left operand");
                self.require_type(
                    &Type::I64,
                    right_type.as_ref(),
                    right.span(),
                    "right operand",
                );
                Type::Bool
            }
            BinaryOperator::And | BinaryOperator::Or => {
                self.require_type(&Type::Bool, left_type.as_ref(), left.span(), "left operand");
                self.require_type(
                    &Type::Bool,
                    right_type.as_ref(),
                    right.span(),
                    "right operand",
                );
                Type::Bool
            }
            BinaryOperator::Equal | BinaryOperator::NotEqual => {
                if let (Some(left_type), Some(right_type)) = (&left_type, &right_type)
                    && left_type != right_type
                {
                    self.diagnostics.push(Diagnostic::error(
                        "J2031",
                        format!(
                            "equality operands differ: {} and {}",
                            left_type.as_str(),
                            right_type.as_str()
                        ),
                        span,
                    ));
                }
                Type::Bool
            }
        }
    }

    fn call_type(
        &mut self,
        function: &str,
        arguments: &[Expression],
        span: Span,
        locals: &HashMap<String, Type>,
        caller: &Function,
    ) -> Option<Type> {
        let Some(signature) = self.signatures.get(function).cloned() else {
            self.diagnostics.push(Diagnostic::error(
                "J2032",
                format!("unknown function `{function}`"),
                span,
            ));
            for argument in arguments {
                self.expression_type(argument, locals, caller);
            }
            return None;
        };
        self.calls
            .entry(caller.name.clone())
            .or_default()
            .push((function.to_owned(), span));
        if arguments.len() != signature.parameters.len() {
            self.diagnostics.push(Diagnostic::error(
                "J2033",
                format!(
                    "function `{function}` expects {} arguments but received {}",
                    signature.parameters.len(),
                    arguments.len()
                ),
                span,
            ));
        }
        for (index, argument) in arguments.iter().enumerate() {
            let actual = self.expression_type(argument, locals, caller);
            if let Some(expected) = signature.parameters.get(index) {
                self.require_type(expected, actual.as_ref(), argument.span(), "call argument");
            }
        }
        let caller_effects = caller.effects.iter().cloned().collect::<BTreeSet<_>>();
        for effect in &signature.effects {
            if !caller_effects.contains(effect) {
                self.diagnostics.push(
                    Diagnostic::error(
                        "J2034",
                        format!(
                            "caller `{}` does not declare callee effect `{effect}`",
                            caller.name
                        ),
                        span,
                    )
                    .with_note("effects are explicit and cannot be acquired through a call"),
                );
            }
        }
        Some(signature.return_type)
    }

    fn require_type(
        &mut self,
        expected: &Type,
        actual: Option<&Type>,
        span: Span,
        context: &'static str,
    ) {
        if let Some(actual) = actual
            && expected != actual
        {
            self.diagnostics.push(Diagnostic::error(
                "J2035",
                format!(
                    "{context} has type {} but {} was required",
                    actual.as_str(),
                    expected.as_str()
                ),
                span,
            ));
        }
    }

    fn check_acyclic_calls(&mut self) {
        let mut visiting = HashSet::new();
        let mut visited = HashSet::new();
        let names = self.signatures.keys().cloned().collect::<Vec<_>>();
        for name in names {
            self.visit(&name, &mut visiting, &mut visited);
        }
    }

    fn visit(&mut self, name: &str, visiting: &mut HashSet<String>, visited: &mut HashSet<String>) {
        if visited.contains(name) {
            return;
        }
        if !visiting.insert(name.to_owned()) {
            let span = self
                .signatures
                .get(name)
                .map_or(self.program.span, |signature| signature.span);
            self.diagnostics.push(
                Diagnostic::error(
                    "J2040",
                    format!("recursive call cycle includes `{name}`"),
                    span,
                )
                .with_note("JOAN v0 forbids recursion to guarantee bounded termination"),
            );
            return;
        }
        let callees = self.calls.get(name).cloned().unwrap_or_default();
        for (callee, span) in callees {
            if visiting.contains(&callee) {
                self.diagnostics.push(
                    Diagnostic::error(
                        "J2040",
                        format!("recursive call cycle from `{name}` to `{callee}`"),
                        span,
                    )
                    .with_note("JOAN v0 forbids recursion to guarantee bounded termination"),
                );
            } else {
                self.visit(&callee, visiting, visited);
            }
        }
        visiting.remove(name);
        visited.insert(name.to_owned());
    }
}
