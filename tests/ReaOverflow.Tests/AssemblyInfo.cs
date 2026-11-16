using Xunit;

// AssemblyRunner/RuntimeRunner capture stdout by swapping the process-global Console.Out while
// executing a loaded assembly's entry point. Running such tests in parallel races on Console.Out
// and makes runtime-equivalence comparisons flaky, so serialize the whole suite.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
