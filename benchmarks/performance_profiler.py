"""
QWED Performance Profiler

Comprehensive performance analysis for all verification engines.
Measures latency, throughput, and memory usage.

Usage:
    python performance_profiler.py
    python performance_profiler.py --engine math
    python performance_profiler.py --report
"""

import time
import json
import statistics
import tracemalloc
import argparse
from datetime import datetime
from typing import List, Callable
from dataclasses import dataclass, asdict
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


@dataclass
class BenchmarkResult:
    """Result of a single benchmark run."""
    engine: str
    operation: str
    iterations: int
    total_time_ms: float
    avg_time_ms: float
    min_time_ms: float
    max_time_ms: float
    std_dev_ms: float
    throughput_per_sec: float
    memory_peak_mb: float
    memory_avg_mb: float
    success_rate: float
    timestamp: str


class PerformanceProfiler:
    """
    Comprehensive performance profiler for QWED engines.
    """
    
    def __init__(self, iterations: int = 100, warmup: int = 5):
        self.iterations = iterations
        self.warmup = warmup
        self.results: List[BenchmarkResult] = []
    
    def benchmark(
        self, 
        name: str,
        engine: str,
        func: Callable,
        *args,
        **kwargs
    ) -> BenchmarkResult:
        """
        Benchmark a single function.
        
        Args:
            name: Name of the operation
            engine: Engine being tested  
            func: Function to benchmark
            *args, **kwargs: Arguments to pass to function
        """
        times = []
        memory_samples = []
        successes = 0
        
        # Warmup runs
        for _ in range(self.warmup):
            try:
                func(*args, **kwargs)
            except Exception:
                pass
        
        # Actual benchmark runs
        for _ in range(self.iterations):
            # Memory tracking
            tracemalloc.start()
            
            start = time.perf_counter()
            try:
                func(*args, **kwargs)
                successes += 1
            except Exception:
                pass
            end = time.perf_counter()
            
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            
            times.append((end - start) * 1000)  # Convert to ms
            memory_samples.append(peak / 1024 / 1024)  # Convert to MB
        
        # Calculate statistics
        avg_time = statistics.mean(times)
        min_time = min(times)
        max_time = max(times)
        std_dev = statistics.stdev(times) if len(times) > 1 else 0
        total_time = sum(times)
        throughput = self.iterations / (total_time / 1000) if total_time > 0 else 0
        memory_peak = max(memory_samples) if memory_samples else 0
        memory_avg = statistics.mean(memory_samples) if memory_samples else 0
        success_rate = successes / self.iterations
        
        result = BenchmarkResult(
            engine=engine,
            operation=name,
            iterations=self.iterations,
            total_time_ms=round(total_time, 3),
            avg_time_ms=round(avg_time, 3),
            min_time_ms=round(min_time, 3),
            max_time_ms=round(max_time, 3),
            std_dev_ms=round(std_dev, 3),
            throughput_per_sec=round(throughput, 1),
            memory_peak_mb=round(memory_peak, 2),
            memory_avg_mb=round(memory_avg, 2),
            success_rate=round(success_rate, 3),
            timestamp=datetime.now().isoformat()
        )
        
        self.results.append(result)
        return result
    
    def print_result(self, result: BenchmarkResult):
        """Pretty print a benchmark result."""
        status = "[OK]" if result.success_rate == 1.0 else "[!]"
        print(f"\n{status} {result.engine} - {result.operation}")
        print(f"   Avg: {result.avg_time_ms:.2f}ms | Min: {result.min_time_ms:.2f}ms | Max: {result.max_time_ms:.2f}ms")
        print(f"   Throughput: {result.throughput_per_sec:.0f}/sec | Memory Peak: {result.memory_peak_mb:.2f}MB")
    
    def save_results(self, filename: str = None):
        """Save results to JSON file."""
        if filename is None:
            filename = f"performance_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        output_path = Path(__file__).parent / filename
        with open(output_path, 'w') as f:
            json.dump([asdict(r) for r in self.results], f, indent=2)
        
        print(f"\n[RESULTS] Results saved to: {output_path}")
        return output_path
    
    def generate_report(self) -> str:
        """Generate a markdown performance report."""
        if not self.results:
            return "No benchmark results available."
        
        lines = [
            "# QWED Performance Report",
            f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Iterations per test:** {self.iterations}",
            "",
            "## Summary",
            "",
            "| Engine | Operation | Avg (ms) | Throughput (/s) | Memory (MB) |",
            "|--------|-----------|----------|-----------------|-------------|"
        ]
        
        for r in self.results:
            lines.append(
                f"| {r.engine} | {r.operation} | {r.avg_time_ms:.2f} | "
                f"{r.throughput_per_sec:.0f} | {r.memory_peak_mb:.2f} |"
            )
        
        # Add recommendations
        lines.extend([
            "",
            "## Performance Analysis",
            ""
        ])
        
        # Find slowest operations
        sorted_by_time = sorted(self.results, key=lambda x: x.avg_time_ms, reverse=True)
        if sorted_by_time:
            slowest = sorted_by_time[0]
            lines.append(f"[!] **Slowest Operation:** {slowest.engine} - {slowest.operation} ({slowest.avg_time_ms:.2f}ms)")
        
        # Find memory-heavy operations
        sorted_by_memory = sorted(self.results, key=lambda x: x.memory_peak_mb, reverse=True)
        if sorted_by_memory:
            heaviest = sorted_by_memory[0]
            lines.append(f"[MEM] **Most Memory:** {heaviest.engine} - {heaviest.operation} ({heaviest.memory_peak_mb:.2f}MB)")
        
        # Recommendations
        lines.extend([
            "",
            "## Recommendations",
            ""
        ])
        
        for r in self.results:
            if r.avg_time_ms > 100:
                lines.append(f"- **{r.engine}/{r.operation}**: Consider caching or optimization (>{100}ms)")
            if r.memory_peak_mb > 50:
                lines.append(f"- **{r.engine}/{r.operation}**: High memory usage, check for leaks")
        
        return "\n".join(lines)


def run_math_benchmarks(profiler: PerformanceProfiler):
    """Benchmark Math Verification Engine."""
    print("\n" + "="*50)
    print("[MATH] MATH ENGINE BENCHMARKS")
    print("="*50)
    
    try:
        from qwed_new.core.verifier import VerificationEngine
        engine = VerificationEngine()
        
        # Simple arithmetic
        result = profiler.benchmark(
            "Simple Arithmetic",
            "Math",
            engine.verify_math,
            "2 * (5 + 10)", 30
        )
        profiler.print_result(result)
        
        # Complex expression
        result = profiler.benchmark(
            "Complex Expression",
            "Math", 
            engine.verify_math,
            "(x**2 + 2*x + 1) / (x + 1)", 
            expected_value=3,
            tolerance=1e-6
        )
        profiler.print_result(result)
        
        # Percentage calculation
        result = profiler.benchmark(
            "Percentage",
            "Math",
            engine.verify_percentage,
            200, 15, 30, "of"
        )
        profiler.print_result(result)
        
    except ImportError as e:
        print(f"[!] Could not import Math Engine: {e}")


def run_dsl_benchmarks(profiler: PerformanceProfiler):
    """Benchmark DSL Parser."""
    print("\n" + "="*50)
    print("[DSL] DSL PARSER BENCHMARKS")
    print("="*50)
    
    try:
        from qwed_new.core.dsl.parser import QWEDLogicDSL
        parser = QWEDLogicDSL()
        
        # Simple expression
        result = profiler.benchmark(
            "Simple Parse",
            "DSL",
            parser.run,
            "(GT x 5)"
        )
        profiler.print_result(result)
        
        # Complex nested expression
        result = profiler.benchmark(
            "Complex Nested",
            "DSL",
            parser.run,
            "(AND (OR (GT x 5) (LT y 10)) (NOT (EQ z 0)))"
        )
        profiler.print_result(result)
        
        # Large expression
        large_expr = "(AND " + " ".join([f"(GT x{i} {i})" for i in range(20)]) + ")"
        result = profiler.benchmark(
            "Large Expression (20 clauses)",
            "DSL",
            parser.run,
            large_expr
        )
        profiler.print_result(result)
        
    except ImportError as e:
        print(f"[!] Could not import DSL Parser: {e}")


def run_symbolic_benchmarks(profiler: PerformanceProfiler):
    """Benchmark Symbolic Verifier."""
    print("\n" + "="*50)
    print("[SYM] SYMBOLIC VERIFIER BENCHMARKS")
    print("="*50)
    
    try:
        from qwed_new.core.symbolic_verifier import SymbolicVerifier
        verifier = SymbolicVerifier()
        
        # Simple code verification
        simple_code = '''
def add(a: int, b: int) -> int:
    return a + b
'''
        result = profiler.benchmark(
            "Simple Code",
            "Symbolic",
            verifier.verify_code,
            simple_code
        )
        profiler.print_result(result)
        
        # Safety properties check
        safety_code = '''
def divide(a: int, b: int) -> float:
    return a / b
'''
        result = profiler.benchmark(
            "Safety Properties",
            "Symbolic",
            verifier.verify_safety_properties,
            safety_code
        )
        profiler.print_result(result)
        
    except ImportError as e:
        print(f"[!] Could not import Symbolic Verifier: {e}")
    except Exception as e:
        print(f"[!] Symbolic Verifier error: {e}")


def run_all_benchmarks():
    """Run all benchmarks."""
    print("\n" + "="*60)
    print("[QWED] QWED PERFORMANCE PROFILER")
    print("="*60)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    profiler = PerformanceProfiler(iterations=50, warmup=3)
    
    run_math_benchmarks(profiler)
    run_dsl_benchmarks(profiler)
    run_symbolic_benchmarks(profiler)
    
    # Save results
    profiler.save_results()
    
    # Generate report
    report = profiler.generate_report()
    report_path = Path(__file__).parent / "PERFORMANCE_REPORT.md"
    with open(report_path, 'w') as f:
        f.write(report)
    print(f"[REPORT] Report saved to: {report_path}")
    
    print("\n" + "="*60)
    print("[DONE] BENCHMARKS COMPLETE")
    print("="*60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="QWED Performance Profiler")
    parser.add_argument("--engine", choices=["math", "dsl", "symbolic", "all"], 
                        default="all", help="Engine to benchmark")
    parser.add_argument("--iterations", type=int, default=50,
                        help="Number of iterations per test")
    parser.add_argument("--report", action="store_true",
                        help="Generate report only (from existing results)")
    
    args = parser.parse_args()
    
    if args.report:
        # Load existing results and generate report
        print("Generating report from existing results...")
    else:
        run_all_benchmarks()
