package com.example.javadebugmcp.debug;

import com.example.javadebugmcp.debug.ValueFormatter.ObjectHandleRegistry;
import com.sun.jdi.AbsentInformationException;
import com.sun.jdi.ArrayReference;
import com.sun.jdi.ArrayType;
import com.sun.jdi.ClassType;
import com.sun.jdi.ClassNotLoadedException;
import com.sun.jdi.Field;
import com.sun.jdi.InterfaceType;
import com.sun.jdi.IncompatibleThreadStateException;
import com.sun.jdi.InvalidTypeException;
import com.sun.jdi.InvocationException;
import com.sun.jdi.LocalVariable;
import com.sun.jdi.Method;
import com.sun.jdi.ObjectReference;
import com.sun.jdi.PrimitiveValue;
import com.sun.jdi.ReferenceType;
import com.sun.jdi.StackFrame;
import com.sun.jdi.StringReference;
import com.sun.jdi.ThreadReference;
import com.sun.jdi.Value;
import com.sun.jdi.VirtualMachine;
import com.sun.source.tree.ArrayAccessTree;
import com.sun.source.tree.BinaryTree;
import com.sun.source.tree.ClassTree;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.ConditionalExpressionTree;
import com.sun.source.tree.ExpressionTree;
import com.sun.source.tree.IdentifierTree;
import com.sun.source.tree.InstanceOfTree;
import com.sun.source.tree.LiteralTree;
import com.sun.source.tree.MemberSelectTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.tree.NewClassTree;
import com.sun.source.tree.ParenthesizedTree;
import com.sun.source.tree.ParameterizedTypeTree;
import com.sun.source.tree.ReturnTree;
import com.sun.source.tree.Tree;
import com.sun.source.tree.TypeCastTree;
import com.sun.source.tree.UnaryTree;
import com.sun.source.util.JavacTask;

import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

final class ExpressionEvaluator {
    private ExpressionEvaluator() {
    }

    static Map<String, Object> evaluate(
            VirtualMachine vm,
            ThreadReference thread,
            int frameIndex,
            ObjectHandleRegistry handleRegistry,
            String expression,
            int invocationOptions)
            throws IncompatibleThreadStateException, InvalidTypeException, ClassNotLoadedException, InvocationException {
        Value value = evaluateValue(vm, thread, frameIndex, expression, invocationOptions);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("threadId", Long.toString(thread.uniqueID()));
        result.put("frameIndex", frameIndex);
        result.put("expression", expression);
        result.put("typeName", typeNameOf(value));
        result.putAll(ValueFormatter.formatValue(value, handleRegistry));
        return result;
    }

    static Value evaluateValue(
            VirtualMachine vm,
            ThreadReference thread,
            int frameIndex,
            String expression,
            int invocationOptions)
            throws IncompatibleThreadStateException, InvalidTypeException, ClassNotLoadedException, InvocationException {
        if (expression == null || expression.isBlank()) {
            throw new IllegalArgumentException("expression must not be blank");
        }
        if (frameIndex < 0) {
            throw new IllegalArgumentException("frameIndex must be >= 0");
        }

        EvaluationContext context = new EvaluationContext(vm, thread, frameIndex, invocationOptions);
        ExpressionTree tree = parseExpression(expression);
        EvaluationTarget target = new Evaluator(context).evaluate(tree);
        if (!(target instanceof ValueTarget valueTarget)) {
            throw new IllegalArgumentException("Expression did not resolve to a value");
        }
        return valueTarget.value();
    }

    private static ExpressionTree parseExpression(String expression) {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            throw new IllegalStateException("System Java compiler is not available");
        }

        String source = "class __ExpressionWrapper__ { Object __eval__() { return " + expression + "; } }";
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        try (StandardJavaFileManager fileManager = compiler.getStandardFileManager(diagnostics, Locale.ROOT, StandardCharsets.UTF_8)) {
            JavaFileObject fileObject = new StringJavaFileObject("ExpressionWrapper.java", source);
            JavacTask task = (JavacTask) compiler.getTask(
                    null,
                    fileManager,
                    diagnostics,
                    List.of("-proc:none"),
                    null,
                    List.of(fileObject));
            Iterable<? extends CompilationUnitTree> units = task.parse();
            for (Diagnostic<? extends JavaFileObject> diagnostic : diagnostics.getDiagnostics()) {
                if (diagnostic.getKind() == Diagnostic.Kind.ERROR) {
                    throw new IllegalArgumentException("Invalid expression: " + diagnostic.getMessage(Locale.ROOT));
                }
            }

            for (CompilationUnitTree unit : units) {
                for (Tree declaration : unit.getTypeDecls()) {
                    if (declaration instanceof ClassTree classTree) {
                        for (Tree member : classTree.getMembers()) {
                            if (member instanceof MethodTree methodTree && "__eval__".contentEquals(methodTree.getName())) {
                                if (methodTree.getBody() == null || methodTree.getBody().getStatements().isEmpty()) {
                                    break;
                                }
                                Tree statement = methodTree.getBody().getStatements().get(0);
                                if (statement instanceof ReturnTree returnTree && returnTree.getExpression() != null) {
                                    return returnTree.getExpression();
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception exception) {
            if (exception instanceof IllegalArgumentException illegalArgumentException) {
                throw illegalArgumentException;
            }
            throw new IllegalStateException("Failed to parse expression", exception);
        }
        throw new IllegalArgumentException("Invalid expression");
    }

    private static String typeNameOf(Value value) {
        return value == null ? null : value.type().name();
    }

    private sealed interface EvaluationTarget permits ValueTarget, ClassTarget {
    }

    private record ValueTarget(Value value) implements EvaluationTarget {
    }

    private record ClassTarget(ReferenceType referenceType) implements EvaluationTarget {
    }

    private record LookupResult(boolean found, Value value) {
    }

    private static final class EvaluationContext {
        private final VirtualMachine vm;
        private final ThreadReference thread;
        private final int frameIndex;
        private final int invocationOptions;

        private EvaluationContext(VirtualMachine vm, ThreadReference thread, int frameIndex, int invocationOptions) {
            this.vm = vm;
            this.thread = thread;
            this.frameIndex = frameIndex;
            this.invocationOptions = invocationOptions;
        }

        private StackFrame frame() throws IncompatibleThreadStateException {
            if (!thread.isSuspended()) {
                throw new IllegalStateException("Thread is not suspended");
            }
            return thread.frame(frameIndex);
        }

        private LookupResult resolveLocal(String name) throws IncompatibleThreadStateException {
            StackFrame frame = frame();
            try {
                for (LocalVariable variable : frame.visibleVariables()) {
                    if (Objects.equals(variable.name(), name)) {
                        return new LookupResult(true, frame.getValue(variable));
                    }
                }
            } catch (AbsentInformationException ignored) {
            }
            LookupResult argument = resolveArgumentAlias(frame, name);
            if (argument.found()) {
                return argument;
            }
            return new LookupResult(false, null);
        }

        private ObjectReference thisObject() throws IncompatibleThreadStateException {
            return frame().thisObject();
        }

        private ReferenceType currentType() throws IncompatibleThreadStateException {
            return frame().location().declaringType();
        }

        private Method currentMethod() throws IncompatibleThreadStateException {
            return frame().location().method();
        }

        private ThreadReference thread() {
            return thread;
        }

        private VirtualMachine vm() {
            return vm;
        }

        private ReferenceType resolveClass(String name) throws IncompatibleThreadStateException {
            LinkedHashSet<String> candidates = new LinkedHashSet<>();
            if (name.contains(".")) {
                addClassCandidates(candidates, name);
            } else {
                addClassCandidates(candidates, name);

                ReferenceType currentType = currentType();
                String currentTypeName = currentType.name();
                String currentPackage = packageName(currentTypeName);
                if (!currentPackage.isEmpty()) {
                    addClassCandidates(candidates, currentPackage + "." + name);
                }
                addClassCandidates(candidates, "java.lang." + name);

                String topLevelType = topLevelTypeName(currentTypeName);
                if (simpleName(currentTypeName).equals(name)) {
                    addClassCandidates(candidates, currentTypeName);
                }
                if (simpleName(topLevelType).equals(name)) {
                    addClassCandidates(candidates, topLevelType);
                }
                addClassCandidates(candidates, topLevelType + "$" + name);
            }

            for (String candidate : candidates) {
                List<ReferenceType> matches = vm.classesByName(candidate);
                if (!matches.isEmpty()) {
                    return matches.get(0);
                }
            }
            return null;
        }

        private ReferenceType resolveNestedClass(ReferenceType owner, String simpleName) {
            for (ReferenceType nestedType : owner.nestedTypes()) {
                if (Objects.equals(ExpressionEvaluator.simpleName(nestedType.name()), simpleName)) {
                    return nestedType;
                }
            }
            return null;
        }

        private LookupResult resolveArgumentAlias(StackFrame frame, String name) {
            Integer index = argumentAliasIndex(name);
            if (index == null) {
                return new LookupResult(false, null);
            }
            List<Value> arguments = frame.getArgumentValues();
            if (index < 0 || index >= arguments.size()) {
                return new LookupResult(false, null);
            }
            return new LookupResult(true, arguments.get(index));
        }
    }

    private static final class Evaluator {
        private final EvaluationContext context;

        private Evaluator(EvaluationContext context) {
            this.context = context;
        }

        private EvaluationTarget evaluate(Tree tree)
                throws IncompatibleThreadStateException, InvalidTypeException, ClassNotLoadedException, InvocationException {
            return switch (tree.getKind()) {
                case PARENTHESIZED -> evaluate(((ParenthesizedTree) tree).getExpression());
                case IDENTIFIER -> evaluateIdentifier((IdentifierTree) tree);
                case MEMBER_SELECT -> evaluateMemberSelect((MemberSelectTree) tree);
                case METHOD_INVOCATION -> evaluateMethodInvocation((MethodInvocationTree) tree);
                case ARRAY_ACCESS -> evaluateArrayAccess((ArrayAccessTree) tree);
                case CONDITIONAL_EXPRESSION -> evaluateConditional((ConditionalExpressionTree) tree);
                case INSTANCE_OF -> evaluateInstanceOf((InstanceOfTree) tree);
                case NEW_CLASS -> evaluateNewClass((NewClassTree) tree);
                case TYPE_CAST -> evaluateTypeCast((TypeCastTree) tree);
                case UNARY_MINUS, UNARY_PLUS, LOGICAL_COMPLEMENT -> evaluateUnary((UnaryTree) tree);
                case MULTIPLY, DIVIDE, REMAINDER, PLUS, MINUS,
                        LESS_THAN, LESS_THAN_EQUAL, GREATER_THAN, GREATER_THAN_EQUAL,
                        EQUAL_TO, NOT_EQUAL_TO, CONDITIONAL_AND, CONDITIONAL_OR -> evaluateBinary((BinaryTree) tree);
                case BOOLEAN_LITERAL, CHAR_LITERAL, DOUBLE_LITERAL, FLOAT_LITERAL,
                        INT_LITERAL, LONG_LITERAL, NULL_LITERAL, STRING_LITERAL -> evaluateLiteral((LiteralTree) tree);
                default -> throw new IllegalArgumentException("Unsupported expression syntax: " + tree.getKind());
            };
        }

        private ValueTarget evaluateLiteral(LiteralTree tree) {
            Object literal = tree.getValue();
            return switch (tree.getKind()) {
                case BOOLEAN_LITERAL -> new ValueTarget(context.vm().mirrorOf((Boolean) literal));
                case CHAR_LITERAL -> new ValueTarget(context.vm().mirrorOf((Character) literal));
                case DOUBLE_LITERAL -> new ValueTarget(context.vm().mirrorOf(((Number) literal).doubleValue()));
                case FLOAT_LITERAL -> new ValueTarget(context.vm().mirrorOf(((Number) literal).floatValue()));
                case INT_LITERAL -> new ValueTarget(context.vm().mirrorOf(((Number) literal).intValue()));
                case LONG_LITERAL -> new ValueTarget(context.vm().mirrorOf(((Number) literal).longValue()));
                case NULL_LITERAL -> new ValueTarget(null);
                case STRING_LITERAL -> new ValueTarget(context.vm().mirrorOf((String) literal));
                default -> throw new IllegalArgumentException("Unsupported literal: " + tree.getKind());
            };
        }

        private EvaluationTarget evaluateIdentifier(IdentifierTree tree) throws IncompatibleThreadStateException {
            String name = tree.getName().toString();
            if ("this".equals(name)) {
                ObjectReference thisObject = context.thisObject();
                if (thisObject == null) {
                    throw new IllegalArgumentException("'this' is not available in the current frame");
                }
                return new ValueTarget(thisObject);
            }

            LookupResult local = context.resolveLocal(name);
            if (local.found()) {
                return new ValueTarget(local.value());
            }

            ObjectReference thisObject = context.thisObject();
            if (thisObject != null) {
                Field instanceField = findField(thisObject.referenceType(), name, false);
                if (instanceField != null) {
                    return new ValueTarget(thisObject.getValue(instanceField));
                }
            }

            ReferenceType currentType = context.currentType();
            Field staticField = findField(currentType, name, true);
            if (staticField != null) {
                return new ValueTarget(currentType.getValue(staticField));
            }

            ReferenceType classReference = context.resolveClass(name);
            if (classReference != null) {
                return new ClassTarget(classReference);
            }
            throw new IllegalArgumentException("Unknown identifier: " + name);
        }

        private EvaluationTarget evaluateMemberSelect(MemberSelectTree tree)
                throws IncompatibleThreadStateException, InvalidTypeException, ClassNotLoadedException, InvocationException {
            try {
                EvaluationTarget base = evaluate(tree.getExpression());
                return accessMember(base, tree.getIdentifier().toString());
            } catch (IllegalArgumentException exception) {
                EvaluationTarget resolved = resolveNameChain(tree);
                if (resolved != null) {
                    return resolved;
                }
                throw exception;
            }
        }

        private ValueTarget evaluateMethodInvocation(MethodInvocationTree tree)
                throws IncompatibleThreadStateException, InvalidTypeException, ClassNotLoadedException, InvocationException {
            List<Value> arguments = evaluateArguments(tree.getArguments());
            ExpressionTree select = tree.getMethodSelect();
            if (select instanceof IdentifierTree identifierTree) {
                return new ValueTarget(invokeUnqualified(identifierTree.getName().toString(), arguments));
            }
            if (select instanceof MemberSelectTree memberSelectTree) {
                EvaluationTarget target = evaluate(memberSelectTree.getExpression());
                return new ValueTarget(invokeOnTarget(target, memberSelectTree.getIdentifier().toString(), arguments));
            }
            throw new IllegalArgumentException("Unsupported method invocation syntax");
        }

        private ValueTarget evaluateArrayAccess(ArrayAccessTree tree)
                throws IncompatibleThreadStateException, InvalidTypeException, ClassNotLoadedException, InvocationException {
            Value arrayValue = requireValue(evaluate(tree.getExpression()), "array access target").value();
            if (!(arrayValue instanceof ArrayReference arrayReference)) {
                throw new IllegalArgumentException("Array access requires an array target");
            }
            int index = requireInt(requireValue(evaluate(tree.getIndex()), "array index").value(), "array index");
            return new ValueTarget(arrayReference.getValue(index));
        }

        private ValueTarget evaluateConditional(ConditionalExpressionTree tree)
                throws IncompatibleThreadStateException, InvalidTypeException, ClassNotLoadedException, InvocationException {
            boolean condition = requireBoolean(requireValue(evaluate(tree.getCondition()), "condition").value(), "condition");
            return requireValue(evaluate(condition ? tree.getTrueExpression() : tree.getFalseExpression()), "conditional result");
        }

        private ValueTarget evaluateInstanceOf(InstanceOfTree tree)
                throws IncompatibleThreadStateException, InvalidTypeException, ClassNotLoadedException, InvocationException {
            Value value = requireValue(evaluate(tree.getExpression()), "instanceof source").value();
            if (value == null) {
                return new ValueTarget(context.vm().mirrorOf(false));
            }
            if (value instanceof PrimitiveValue) {
                throw new IllegalArgumentException("instanceof requires a reference value");
            }

            String targetTypeName = typeNameFromTree(tree.getType());
            ReferenceType targetType = context.resolveClass(targetTypeName);
            if (targetType == null) {
                throw new IllegalArgumentException("Class not loaded for instanceof target: " + targetTypeName);
            }
            boolean matched = referenceDistance(((ObjectReference) value).referenceType(), targetType.name()) != null;
            return new ValueTarget(context.vm().mirrorOf(matched));
        }

        private ValueTarget evaluateNewClass(NewClassTree tree)
                throws IncompatibleThreadStateException, InvalidTypeException, ClassNotLoadedException, InvocationException {
            if (tree.getClassBody() != null) {
                throw new IllegalArgumentException("Anonymous class creation is not supported");
            }
            if (tree.getEnclosingExpression() != null) {
                throw new IllegalArgumentException("Qualified inner class creation is not supported");
            }

            String typeName = typeNameFromTree(tree.getIdentifier());
            List<Value> arguments = evaluateArguments(tree.getArguments());
            return new ValueTarget(invokeConstructor(typeName, arguments));
        }

        private ValueTarget evaluateTypeCast(TypeCastTree tree)
                throws IncompatibleThreadStateException, InvalidTypeException, ClassNotLoadedException, InvocationException {
            Value value = requireValue(evaluate(tree.getExpression()), "cast source").value();
            String targetTypeName = typeNameFromTree(tree.getType());
            if (isPrimitiveType(targetTypeName)) {
                Conversion conversion = convertArgument(value, targetTypeName);
                if (conversion == null) {
                    throw new IllegalArgumentException("Cannot cast to " + targetTypeName);
                }
                return new ValueTarget(conversion.value());
            }
            if (value == null) {
                return new ValueTarget(null);
            }
            if (value instanceof PrimitiveValue) {
                throw new IllegalArgumentException("Cannot cast primitive to reference type " + targetTypeName);
            }
            ReferenceType targetType = context.resolveClass(targetTypeName);
            if (targetType == null) {
                throw new IllegalArgumentException("Class not loaded for cast target: " + targetTypeName);
            }
            if (referenceDistance(((ObjectReference) value).referenceType(), targetType.name()) == null) {
                throw new IllegalArgumentException("Value is not assignable to " + targetTypeName);
            }
            return new ValueTarget(value);
        }

        private ValueTarget evaluateUnary(UnaryTree tree)
                throws IncompatibleThreadStateException, InvalidTypeException, ClassNotLoadedException, InvocationException {
            Value value = requireValue(evaluate(tree.getExpression()), "unary operand").value();
            return switch (tree.getKind()) {
                case UNARY_MINUS -> new ValueTarget(negateNumeric(value));
                case UNARY_PLUS -> new ValueTarget(requireNumericValue(value, "unary plus"));
                case LOGICAL_COMPLEMENT -> new ValueTarget(context.vm().mirrorOf(!requireBoolean(value, "logical complement")));
                default -> throw new IllegalArgumentException("Unsupported unary operator: " + tree.getKind());
            };
        }

        private ValueTarget evaluateBinary(BinaryTree tree)
                throws IncompatibleThreadStateException, InvalidTypeException, ClassNotLoadedException, InvocationException {
            if (tree.getKind() == Tree.Kind.CONDITIONAL_AND) {
                boolean left = requireBoolean(requireValue(evaluate(tree.getLeftOperand()), "left operand").value(), "left operand");
                if (!left) {
                    return new ValueTarget(context.vm().mirrorOf(false));
                }
                boolean right = requireBoolean(requireValue(evaluate(tree.getRightOperand()), "right operand").value(), "right operand");
                return new ValueTarget(context.vm().mirrorOf(right));
            }
            if (tree.getKind() == Tree.Kind.CONDITIONAL_OR) {
                boolean left = requireBoolean(requireValue(evaluate(tree.getLeftOperand()), "left operand").value(), "left operand");
                if (left) {
                    return new ValueTarget(context.vm().mirrorOf(true));
                }
                boolean right = requireBoolean(requireValue(evaluate(tree.getRightOperand()), "right operand").value(), "right operand");
                return new ValueTarget(context.vm().mirrorOf(right));
            }

            Value left = requireValue(evaluate(tree.getLeftOperand()), "left operand").value();
            Value right = requireValue(evaluate(tree.getRightOperand()), "right operand").value();
            return switch (tree.getKind()) {
                case PLUS -> new ValueTarget(addValues(left, right));
                case MINUS -> new ValueTarget(applyNumericBinary(left, right, tree.getKind()));
                case MULTIPLY -> new ValueTarget(applyNumericBinary(left, right, tree.getKind()));
                case DIVIDE -> new ValueTarget(applyNumericBinary(left, right, tree.getKind()));
                case REMAINDER -> new ValueTarget(applyNumericBinary(left, right, tree.getKind()));
                case LESS_THAN -> new ValueTarget(context.vm().mirrorOf(compareNumeric(left, right) < 0));
                case LESS_THAN_EQUAL -> new ValueTarget(context.vm().mirrorOf(compareNumeric(left, right) <= 0));
                case GREATER_THAN -> new ValueTarget(context.vm().mirrorOf(compareNumeric(left, right) > 0));
                case GREATER_THAN_EQUAL -> new ValueTarget(context.vm().mirrorOf(compareNumeric(left, right) >= 0));
                case EQUAL_TO -> new ValueTarget(context.vm().mirrorOf(equalsValue(left, right)));
                case NOT_EQUAL_TO -> new ValueTarget(context.vm().mirrorOf(!equalsValue(left, right)));
                default -> throw new IllegalArgumentException("Unsupported binary operator: " + tree.getKind());
            };
        }

        private EvaluationTarget resolveNameChain(Tree tree)
                throws IncompatibleThreadStateException, InvalidTypeException, ClassNotLoadedException, InvocationException {
            List<String> parts = flattenName(tree);
            if (parts == null) {
                return null;
            }
            for (int split = parts.size(); split >= 1; split--) {
                String candidate = String.join(".", parts.subList(0, split));
                ReferenceType classReference = context.resolveClass(candidate);
                if (classReference == null) {
                    continue;
                }
                EvaluationTarget current = new ClassTarget(classReference);
                for (String member : parts.subList(split, parts.size())) {
                    current = accessMember(current, member);
                }
                return current;
            }
            return null;
        }

        private List<String> flattenName(Tree tree) {
            if (tree instanceof IdentifierTree identifierTree) {
                return List.of(identifierTree.getName().toString());
            }
            if (tree instanceof MemberSelectTree memberSelectTree) {
                List<String> prefix = flattenName(memberSelectTree.getExpression());
                if (prefix == null) {
                    return null;
                }
                List<String> result = new ArrayList<>(prefix);
                result.add(memberSelectTree.getIdentifier().toString());
                return result;
            }
            return null;
        }

        private EvaluationTarget accessMember(EvaluationTarget target, String member) throws IncompatibleThreadStateException {
            if (target instanceof ClassTarget classTarget) {
                Field staticField = findField(classTarget.referenceType(), member, true);
                if (staticField != null) {
                    return new ValueTarget(classTarget.referenceType().getValue(staticField));
                }
                ReferenceType nestedType = context.resolveNestedClass(classTarget.referenceType(), member);
                if (nestedType != null) {
                    return new ClassTarget(nestedType);
                }
                throw new IllegalArgumentException("Unknown static member: " + classTarget.referenceType().name() + "." + member);
            }

            Value value = requireValue(target, "member access target").value();
            if (value == null) {
                throw new IllegalArgumentException("Cannot access member '" + member + "' on null");
            }
            if (value instanceof ArrayReference arrayReference && "length".equals(member)) {
                return new ValueTarget(context.vm().mirrorOf(arrayReference.length()));
            }
            if (!(value instanceof ObjectReference objectReference)) {
                throw new IllegalArgumentException("Member access requires an object target");
            }
            Field field = findField(objectReference.referenceType(), member, false);
            if (field != null) {
                return new ValueTarget(objectReference.getValue(field));
            }
            Field staticField = findField(objectReference.referenceType(), member, true);
            if (staticField != null) {
                return new ValueTarget(objectReference.referenceType().getValue(staticField));
            }
            throw new IllegalArgumentException("Unknown member: " + objectReference.referenceType().name() + "." + member);
        }

        private List<Value> evaluateArguments(List<? extends ExpressionTree> trees)
                throws IncompatibleThreadStateException, InvalidTypeException, ClassNotLoadedException, InvocationException {
            List<Value> values = new ArrayList<>(trees.size());
            for (ExpressionTree tree : trees) {
                values.add(requireValue(evaluate(tree), "argument").value());
            }
            return values;
        }

        private Value invokeUnqualified(String methodName, List<Value> arguments)
                throws IncompatibleThreadStateException, InvalidTypeException, ClassNotLoadedException, InvocationException {
            MethodSelection best = null;

            ObjectReference thisObject = context.thisObject();
            if (thisObject != null) {
                best = betterSelection(best, selectMethod(thisObject.referenceType(), methodName, false, arguments));
            }
            best = betterSelection(best, selectMethod(context.currentType(), methodName, true, arguments));

            if (best == null) {
                throw new IllegalArgumentException("No applicable method named '" + methodName + "'");
            }
            return invokeSelection(best, thisObject);
        }

        private Value invokeOnTarget(EvaluationTarget target, String methodName, List<Value> arguments)
                throws IncompatibleThreadStateException, InvalidTypeException, ClassNotLoadedException, InvocationException {
            if (target instanceof ClassTarget classTarget) {
                MethodSelection selection = selectMethod(classTarget.referenceType(), methodName, true, arguments);
                if (selection == null) {
                    throw new IllegalArgumentException("No applicable static method: " + classTarget.referenceType().name() + "." + methodName);
                }
                return invokeSelection(selection, null);
            }

            Value receiver = requireValue(target, "method target").value();
            if (!(receiver instanceof ObjectReference objectReference)) {
                throw new IllegalArgumentException("Method invocation requires an object or class target");
            }
            MethodSelection selection = selectMethod(objectReference.referenceType(), methodName, false, arguments);
            if (selection == null) {
                throw new IllegalArgumentException("No applicable method: " + objectReference.referenceType().name() + "." + methodName);
            }
            return invokeSelection(selection, objectReference);
        }

        private Value invokeConstructor(String typeName, List<Value> arguments)
                throws IncompatibleThreadStateException, InvalidTypeException, ClassNotLoadedException, InvocationException {
            ReferenceType referenceType = context.resolveClass(typeName);
            if (referenceType == null) {
                throw new IllegalArgumentException("Class not loaded for constructor: " + typeName);
            }
            if (referenceType instanceof ArrayType) {
                throw new IllegalArgumentException("Array construction is not supported");
            }
            if (!(referenceType instanceof ClassType classType)) {
                throw new IllegalArgumentException("Cannot instantiate non-class type: " + referenceType.name());
            }
            if (classType.isAbstract()) {
                throw new IllegalArgumentException("Cannot instantiate abstract class: " + classType.name());
            }

            MethodSelection constructor = selectConstructor(classType, arguments);
            if (constructor == null) {
                throw new IllegalArgumentException("No applicable constructor for " + classType.name());
            }

            try {
                return classType.newInstance(
                        context.thread(),
                        constructor.method(),
                        constructor.arguments(),
                        context.invocationOptions);
            } catch (InvocationException exception) {
                throw invocationFailed(exception);
            }
        }

        private Value invokeSelection(MethodSelection selection, ObjectReference receiver)
                throws InvalidTypeException, ClassNotLoadedException, IncompatibleThreadStateException, InvocationException {
            try {
                if (selection.staticInvocation()) {
                    if (selection.ownerType() instanceof ClassType classType) {
                        return classType.invokeMethod(context.thread(), selection.method(), selection.arguments(), context.invocationOptions);
                    }
                    if (selection.ownerType() instanceof InterfaceType interfaceType) {
                        return interfaceType.invokeMethod(context.thread(), selection.method(), selection.arguments(), context.invocationOptions);
                    }
                    throw new IllegalArgumentException("Static invocation is not supported for " + selection.ownerType().name());
                }
                if (receiver == null) {
                    throw new IllegalArgumentException("Instance receiver is required for " + selection.method().name());
                }
                return receiver.invokeMethod(context.thread(), selection.method(), selection.arguments(), context.invocationOptions);
            } catch (InvocationException exception) {
                throw invocationFailed(exception);
            }
        }

        private MethodSelection selectMethod(ReferenceType ownerType, String methodName, boolean staticInvocation, List<Value> arguments) {
            MethodSelection best = null;
            for (Method method : ownerType.allMethods()) {
                if (!Objects.equals(method.name(), methodName) || method.isStatic() != staticInvocation) {
                    continue;
                }
                MethodSelection candidate = buildSelection(ownerType, method, arguments, staticInvocation);
                if (candidate == null) {
                    continue;
                }
                best = betterSelection(best, candidate);
            }
            return best;
        }

        private MethodSelection selectConstructor(ClassType ownerType, List<Value> arguments) {
            MethodSelection best = null;
            for (Method method : ownerType.methods()) {
                if (!method.isConstructor()) {
                    continue;
                }
                MethodSelection candidate = buildSelection(ownerType, method, arguments, false);
                if (candidate == null) {
                    continue;
                }
                best = betterSelection(best, candidate);
            }
            return best;
        }

        private MethodSelection buildSelection(ReferenceType ownerType, Method method, List<Value> arguments, boolean staticInvocation) {
            List<String> parameterTypes = method.argumentTypeNames();
            if (parameterTypes.size() != arguments.size()) {
                return null;
            }
            List<Value> convertedArguments = new ArrayList<>(arguments.size());
            int score = 0;
            for (int index = 0; index < arguments.size(); index++) {
                Conversion conversion = convertArgument(arguments.get(index), parameterTypes.get(index));
                if (conversion == null) {
                    return null;
                }
                convertedArguments.add(conversion.value());
                score += conversion.score();
            }
            if (!Objects.equals(ownerType, method.declaringType())) {
                Integer declaringTypeDistance = referenceDistance(ownerType, method.declaringType().name());
                score += declaringTypeDistance == null ? 100 : declaringTypeDistance;
            }
            return new MethodSelection(ownerType, method, List.copyOf(convertedArguments), score, staticInvocation);
        }

        private MethodSelection betterSelection(MethodSelection existing, MethodSelection candidate) {
            if (candidate == null) {
                return existing;
            }
            if (existing == null || candidate.score() < existing.score()) {
                return candidate;
            }
            if (candidate.score() == existing.score() && !Objects.equals(candidate.method(), existing.method())) {
                throw new IllegalArgumentException("Ambiguous method invocation: " + candidate.method().name());
            }
            return existing;
        }

        private Field findField(ReferenceType referenceType, String name, boolean staticOnly) {
            for (Field field : referenceType.allFields()) {
                if (Objects.equals(field.name(), name) && field.isStatic() == staticOnly) {
                    return field;
                }
            }
            return null;
        }

        private ValueTarget requireValue(EvaluationTarget target, String description) {
            if (target instanceof ValueTarget valueTarget) {
                return valueTarget;
            }
            throw new IllegalArgumentException(description + " must resolve to a value");
        }

        private boolean requireBoolean(Value value, String description) {
            if (!(value instanceof PrimitiveValue primitiveValue) || !"boolean".equals(primitiveTypeName(primitiveValue))) {
                throw new IllegalArgumentException(description + " must be boolean");
            }
            return primitiveValue.booleanValue();
        }

        private int requireInt(Value value, String description) {
            PrimitiveValue primitiveValue = requireNumericValue(value, description);
            return switch (primitiveTypeName(primitiveValue)) {
                case "byte", "short", "int" -> primitiveValue.intValue();
                case "char" -> primitiveValue.charValue();
                default -> throw new IllegalArgumentException(description + " must be int-compatible");
            };
        }

        private PrimitiveValue requireNumericValue(Value value, String description) {
            if (!(value instanceof PrimitiveValue primitiveValue) || "boolean".equals(primitiveTypeName(primitiveValue))) {
                throw new IllegalArgumentException(description + " must be numeric");
            }
            return primitiveValue;
        }

        private Value negateNumeric(Value value) {
            PrimitiveValue primitiveValue = requireNumericValue(value, "unary minus");
            String typeName = unaryPromotionType(primitiveValue);
            return switch (typeName) {
                case "double" -> context.vm().mirrorOf(-primitiveValue.doubleValue());
                case "float" -> context.vm().mirrorOf(-primitiveValue.floatValue());
                case "long" -> context.vm().mirrorOf(-primitiveValue.longValue());
                default -> context.vm().mirrorOf(-toInt(primitiveValue));
            };
        }

        private Value addValues(Value left, Value right)
                throws IncompatibleThreadStateException, InvalidTypeException, ClassNotLoadedException, InvocationException {
            if (isStringValue(left) || isStringValue(right)) {
                return context.vm().mirrorOf(coerceToString(left) + coerceToString(right));
            }
            return applyNumericBinary(left, right, Tree.Kind.PLUS);
        }

        private Value applyNumericBinary(Value left, Value right, Tree.Kind operator) {
            PrimitiveValue leftValue = requireNumericValue(left, "left operand");
            PrimitiveValue rightValue = requireNumericValue(right, "right operand");
            String typeName = binaryPromotionType(leftValue, rightValue);
            return switch (typeName) {
                case "double" -> context.vm().mirrorOf(applyDouble(operator, leftValue.doubleValue(), rightValue.doubleValue()));
                case "float" -> context.vm().mirrorOf((float) applyDouble(operator, leftValue.floatValue(), rightValue.floatValue()));
                case "long" -> context.vm().mirrorOf(applyLong(operator, leftValue.longValue(), rightValue.longValue()));
                default -> context.vm().mirrorOf(applyInt(operator, toInt(leftValue), toInt(rightValue)));
            };
        }

        private int compareNumeric(Value left, Value right) {
            PrimitiveValue leftValue = requireNumericValue(left, "left operand");
            PrimitiveValue rightValue = requireNumericValue(right, "right operand");
            String typeName = binaryPromotionType(leftValue, rightValue);
            return switch (typeName) {
                case "double" -> Double.compare(leftValue.doubleValue(), rightValue.doubleValue());
                case "float" -> Float.compare(leftValue.floatValue(), rightValue.floatValue());
                case "long" -> Long.compare(leftValue.longValue(), rightValue.longValue());
                default -> Integer.compare(toInt(leftValue), toInt(rightValue));
            };
        }

        private boolean equalsValue(Value left, Value right) {
            if (left == null || right == null) {
                return left == right;
            }
            if (left instanceof PrimitiveValue || right instanceof PrimitiveValue) {
                if (!(left instanceof PrimitiveValue) || !(right instanceof PrimitiveValue)) {
                    throw new IllegalArgumentException("Cannot compare primitive and reference values");
                }
                if ("boolean".equals(primitiveTypeName((PrimitiveValue) left))
                        || "boolean".equals(primitiveTypeName((PrimitiveValue) right))) {
                    return requireBoolean(left, "left operand") == requireBoolean(right, "right operand");
                }
                return compareNumeric(left, right) == 0;
            }
            return ((ObjectReference) left).uniqueID() == ((ObjectReference) right).uniqueID();
        }

        private Conversion convertArgument(Value value, String targetTypeName) {
            if (isPrimitiveType(targetTypeName)) {
                return convertPrimitiveArgument(value, targetTypeName);
            }
            if (value == null) {
                return new Conversion(null, 10);
            }
            if (!(value instanceof ObjectReference objectReference)) {
                return null;
            }
            Integer distance = referenceDistance(objectReference.referenceType(), targetTypeName);
            if (distance == null) {
                return null;
            }
            return new Conversion(value, distance);
        }

        private Conversion convertPrimitiveArgument(Value value, String targetTypeName) {
            if (!(value instanceof PrimitiveValue primitiveValue)) {
                return null;
            }
            String actualType = primitiveTypeName(primitiveValue);
            if (Objects.equals(actualType, targetTypeName)) {
                return new Conversion(primitiveValue, 0);
            }
            if ("boolean".equals(actualType) || "boolean".equals(targetTypeName)) {
                return null;
            }
            int distance = primitiveWideningDistance(actualType, targetTypeName);
            if (distance < 0) {
                return null;
            }
            return new Conversion(mirrorPrimitive(primitiveValue, targetTypeName), distance);
        }

        private Integer referenceDistance(ReferenceType actualType, String targetTypeName) {
            if (Objects.equals(actualType.name(), targetTypeName)) {
                return 0;
            }
            if (actualType.name().endsWith("[]")) {
                if ("java.lang.Object".equals(targetTypeName)
                        || "java.lang.Cloneable".equals(targetTypeName)
                        || "java.io.Serializable".equals(targetTypeName)) {
                    return 1;
                }
                return null;
            }

            Set<String> visited = new LinkedHashSet<>();
            List<ReferenceType> frontier = List.of(actualType);
            int distance = 0;
            while (!frontier.isEmpty()) {
                List<ReferenceType> next = new ArrayList<>();
                for (ReferenceType candidate : frontier) {
                    if (!visited.add(candidate.name())) {
                        continue;
                    }
                    if (Objects.equals(candidate.name(), targetTypeName)) {
                        return distance;
                    }
                    next.addAll(directSupertypes(candidate));
                }
                frontier = next;
                distance++;
            }
            return null;
        }

        private List<ReferenceType> directSupertypes(ReferenceType referenceType) {
            List<ReferenceType> result = new ArrayList<>();
            if (referenceType instanceof ClassType classType) {
                if (classType.superclass() != null) {
                    result.add(classType.superclass());
                }
                result.addAll(classType.interfaces());
            } else if (referenceType instanceof InterfaceType interfaceType) {
                result.addAll(interfaceType.superinterfaces());
            }
            return result;
        }

        private String coerceToString(Value value)
                throws IncompatibleThreadStateException, InvalidTypeException, ClassNotLoadedException, InvocationException {
            if (value == null) {
                return "null";
            }
            if (value instanceof StringReference stringReference) {
                return stringReference.value();
            }
            if (value instanceof PrimitiveValue primitiveValue) {
                return primitiveToString(primitiveValue);
            }

            ReferenceType stringType = context.resolveClass("java.lang.String");
            if (stringType != null) {
                MethodSelection selection = selectMethod(stringType, "valueOf", true, List.of(value));
                if (selection != null) {
                    Value result = invokeSelection(selection, null);
                    if (result instanceof StringReference stringReference) {
                        return stringReference.value();
                    }
                }
            }

            ObjectReference objectReference = (ObjectReference) value;
            return objectReference.referenceType().name() + "@" + objectReference.uniqueID();
        }

        private IllegalStateException invocationFailed(InvocationException exception) {
            ObjectReference thrown = exception.exception();
            String typeName = thrown.referenceType().name();
            String message = readThrowableMessage(thrown);
            String text = message == null || message.isBlank()
                    ? "Expression invocation threw " + typeName
                    : "Expression invocation threw " + typeName + ": " + message;
            return new IllegalStateException(text, exception);
        }

        private String readThrowableMessage(ObjectReference throwable) {
            Field messageField = throwable.referenceType().fieldByName("detailMessage");
            if (messageField == null) {
                return null;
            }
            Value messageValue = throwable.getValue(messageField);
            if (messageValue instanceof StringReference stringReference) {
                return stringReference.value();
            }
            return null;
        }

        private boolean isStringValue(Value value) {
            return value instanceof StringReference;
        }

        private String primitiveTypeName(PrimitiveValue value) {
            return value.type().name();
        }

        private String unaryPromotionType(PrimitiveValue value) {
            return switch (primitiveTypeName(value)) {
                case "double" -> "double";
                case "float" -> "float";
                case "long" -> "long";
                default -> "int";
            };
        }

        private String binaryPromotionType(PrimitiveValue left, PrimitiveValue right) {
            List<String> types = List.of(primitiveTypeName(left), primitiveTypeName(right));
            if (types.contains("double")) {
                return "double";
            }
            if (types.contains("float")) {
                return "float";
            }
            if (types.contains("long")) {
                return "long";
            }
            return "int";
        }

        private int primitiveWideningDistance(String actualType, String targetType) {
            return switch (actualType) {
                case "byte" -> switch (targetType) {
                    case "short" -> 1;
                    case "int" -> 2;
                    case "long" -> 3;
                    case "float" -> 4;
                    case "double" -> 5;
                    default -> -1;
                };
                case "short" -> switch (targetType) {
                    case "int" -> 1;
                    case "long" -> 2;
                    case "float" -> 3;
                    case "double" -> 4;
                    default -> -1;
                };
                case "char" -> switch (targetType) {
                    case "int" -> 1;
                    case "long" -> 2;
                    case "float" -> 3;
                    case "double" -> 4;
                    default -> -1;
                };
                case "int" -> switch (targetType) {
                    case "long" -> 1;
                    case "float" -> 2;
                    case "double" -> 3;
                    default -> -1;
                };
                case "long" -> switch (targetType) {
                    case "float" -> 1;
                    case "double" -> 2;
                    default -> -1;
                };
                case "float" -> "double".equals(targetType) ? 1 : -1;
                default -> -1;
            };
        }

        private Value mirrorPrimitive(PrimitiveValue value, String targetTypeName) {
            return switch (targetTypeName) {
                case "byte" -> context.vm().mirrorOf(value.byteValue());
                case "short" -> context.vm().mirrorOf(value.shortValue());
                case "char" -> context.vm().mirrorOf(value.charValue());
                case "int" -> context.vm().mirrorOf(toInt(value));
                case "long" -> context.vm().mirrorOf(value.longValue());
                case "float" -> context.vm().mirrorOf(value.floatValue());
                case "double" -> context.vm().mirrorOf(value.doubleValue());
                case "boolean" -> context.vm().mirrorOf(value.booleanValue());
                default -> throw new IllegalArgumentException("Unsupported primitive type: " + targetTypeName);
            };
        }

        private int toInt(PrimitiveValue value) {
            return "char".equals(primitiveTypeName(value)) ? value.charValue() : value.intValue();
        }

        private int applyInt(Tree.Kind operator, int left, int right) {
            return switch (operator) {
                case PLUS -> left + right;
                case MINUS -> left - right;
                case MULTIPLY -> left * right;
                case DIVIDE -> left / right;
                case REMAINDER -> left % right;
                default -> throw new IllegalArgumentException("Unsupported numeric operator: " + operator);
            };
        }

        private long applyLong(Tree.Kind operator, long left, long right) {
            return switch (operator) {
                case PLUS -> left + right;
                case MINUS -> left - right;
                case MULTIPLY -> left * right;
                case DIVIDE -> left / right;
                case REMAINDER -> left % right;
                default -> throw new IllegalArgumentException("Unsupported numeric operator: " + operator);
            };
        }

        private double applyDouble(Tree.Kind operator, double left, double right) {
            return switch (operator) {
                case PLUS -> left + right;
                case MINUS -> left - right;
                case MULTIPLY -> left * right;
                case DIVIDE -> left / right;
                case REMAINDER -> left % right;
                default -> throw new IllegalArgumentException("Unsupported numeric operator: " + operator);
            };
        }

        private String primitiveToString(PrimitiveValue value) {
            return switch (primitiveTypeName(value)) {
                case "boolean" -> Boolean.toString(value.booleanValue());
                case "char" -> Character.toString(value.charValue());
                case "byte" -> Byte.toString(value.byteValue());
                case "short" -> Short.toString(value.shortValue());
                case "int" -> Integer.toString(value.intValue());
                case "long" -> Long.toString(value.longValue());
                case "float" -> Float.toString(value.floatValue());
                case "double" -> Double.toString(value.doubleValue());
                default -> value.toString();
            };
        }
    }

    private record Conversion(Value value, int score) {
    }

    private record MethodSelection(
            ReferenceType ownerType,
            Method method,
            List<Value> arguments,
            int score,
            boolean staticInvocation) {
    }

    private static void addClassCandidates(Set<String> candidates, String className) {
        candidates.add(className);
        String variant = className;
        while (variant.contains(".")) {
            int separator = variant.lastIndexOf('.');
            variant = variant.substring(0, separator) + "$" + variant.substring(separator + 1);
            candidates.add(variant);
        }
    }

    private static String packageName(String typeName) {
        int separator = typeName.lastIndexOf('.');
        return separator < 0 ? "" : typeName.substring(0, separator);
    }

    private static String topLevelTypeName(String typeName) {
        int separator = typeName.indexOf('$');
        return separator < 0 ? typeName : typeName.substring(0, separator);
    }

    private static String simpleName(String typeName) {
        int packageSeparator = typeName.lastIndexOf('.');
        String withoutPackage = packageSeparator < 0 ? typeName : typeName.substring(packageSeparator + 1);
        int nestedSeparator = withoutPackage.lastIndexOf('$');
        return nestedSeparator < 0 ? withoutPackage : withoutPackage.substring(nestedSeparator + 1);
    }

    private static String typeNameFromTree(Tree tree) {
        if (tree instanceof ParameterizedTypeTree parameterizedTypeTree) {
            return typeNameFromTree(parameterizedTypeTree.getType());
        }
        return normalizeTypeName(tree.toString());
    }

    private static String normalizeTypeName(String rawTypeName) {
        StringBuilder builder = new StringBuilder();
        int genericDepth = 0;
        for (int index = 0; index < rawTypeName.length(); index++) {
            char current = rawTypeName.charAt(index);
            if (current == '<') {
                genericDepth++;
                continue;
            }
            if (current == '>') {
                genericDepth--;
                continue;
            }
            if (genericDepth == 0 && !Character.isWhitespace(current)) {
                builder.append(current);
            }
        }
        return builder.toString();
    }

    private static Integer argumentAliasIndex(String name) {
        if (name.startsWith("param")) {
            return parseNonNegativeInt(name.substring(5));
        }
        if (name.startsWith("arg")) {
            return parseNonNegativeInt(name.substring(3));
        }
        if (name.startsWith("p")) {
            return parseNonNegativeInt(name.substring(1));
        }
        return null;
    }

    private static Integer parseNonNegativeInt(String text) {
        if (text.isEmpty()) {
            return null;
        }
        for (int index = 0; index < text.length(); index++) {
            if (!Character.isDigit(text.charAt(index))) {
                return null;
            }
        }
        return Integer.parseInt(text);
    }

    private static boolean isPrimitiveType(String typeName) {
        return switch (typeName) {
            case "boolean", "byte", "short", "char", "int", "long", "float", "double" -> true;
            default -> false;
        };
    }

    private static final class StringJavaFileObject extends SimpleJavaFileObject {
        private final String source;

        private StringJavaFileObject(String fileName, String source) {
            super(URI.create("string:///" + fileName), JavaFileObject.Kind.SOURCE);
            this.source = source;
        }

        @Override
        public CharSequence getCharContent(boolean ignoreEncodingErrors) {
            return source;
        }
    }
}
