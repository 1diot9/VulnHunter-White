package com.example.javadebugmcp.fixture;

public final class SampleDebuggee {
    private SampleDebuggee() {
    }

    public static void main(String[] args) throws Exception {
        System.out.println("READY");
        System.out.flush();

        long endAt = System.currentTimeMillis() + 15000L;
        int index = 0;
        while (System.currentTimeMillis() < endAt) {
            String result = exercise("user-" + index);
            if (result.isEmpty()) {
                throw new IllegalStateException("unexpected empty result");
            }
            String instanceResult = new SampleDebuggee().instanceExercise("user-" + index);
            if (instanceResult.isEmpty()) {
                throw new IllegalStateException("unexpected empty instance result");
            }
            greet("user-" + index);
            add(index, index + 1);
            if (index >= 3) {
                swallowExceptionPath();
            }
            if (index >= 5) {
                launchParallelWorkers();
            }
            Thread.sleep(200L);
            index++;
        }
    }

    static String exercise(String input) {
        String stage1 = input.trim();
        String stage2 = stage1 + "-checked";
        sink(stage2); // BREAKPOINT_EXERCISE
        return stage2;
    }

    static void sink(String value) {
        if (value == null) {
            throw new IllegalArgumentException("value");
        }
        if (value.startsWith("never")) {
            throw new IllegalStateException(value);
        }
    }

    static void swallowExceptionPath() {
        try {
            throwAndCatch();
        } catch (IllegalArgumentException ignored) {
            // Keep the process alive so the debugger can observe the exception event.
        }
    }

    static void throwAndCatch() {
        throw new IllegalArgumentException("boom-marker");
    }

    // --- Methods used by new feature tests ---

    static String greet(String name) {
        String greeting = "Hello, " + name + "!"; // BREAKPOINT_GREET
        return greeting;
    }

    static int add(int a, int b) {
        int sum = a + b; // BREAKPOINT_ADD
        return sum;
    }

    String instanceExercise(String input) {
        return input + "!"; // BREAKPOINT_INSTANCE
    }

    static void launchParallelWorkers() throws InterruptedException {
        Thread left = new Thread(() -> parallelExercise("left"), "parallel-left");
        Thread right = new Thread(() -> parallelExercise("right"), "parallel-right");
        left.start();
        right.start();
        left.join();
        right.join();
    }

    static String parallelExercise(String label) {
        String value = label + "-parallel";
        sink(value); // BREAKPOINT_PARALLEL
        return value;
    }

    public static String blockingProbe(String label, long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("probe interrupted", exception);
        }
        return label;
    }
}
