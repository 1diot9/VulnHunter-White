package com.example.javadebugmcp.debug;

import java.util.List;

final class ExceptionBreakpointConfig {
    final boolean caught;
    final boolean uncaught;
    final String classFilter;
    final List<String> classExclusionFilters;
    final List<String> exceptionTypes;

    ExceptionBreakpointConfig(
            boolean caught,
            boolean uncaught,
            String classFilter,
            List<String> classExclusionFilters,
            List<String> exceptionTypes) {
        this.caught = caught;
        this.uncaught = uncaught;
        this.classFilter = classFilter;
        this.classExclusionFilters = List.copyOf(classExclusionFilters);
        this.exceptionTypes = List.copyOf(exceptionTypes);
    }
}
