"""
Main entry point for running Deep Benchmark Suite.
"""
import asyncio
from benchmarks.deep_suite.generators.math_generator import MathGenerator
from benchmarks.deep_suite.runners.math_runner import MathRunner
from benchmarks.deep_suite.reporter.reporter import DeepReporter

async def main():
    print("🚀 Starting Deep Benchmark Suite...")
    
    # 1. Generate Math Suite
    print("\n🧮 Generating Math Problems...")
    math_gen = MathGenerator()
    math_suite = math_gen.generate_suite(count_per_level=3) # Small count for quick test
    print(f"Generated {len(math_suite)} math problems.")
    
    # 2. Run Math Runner
    print("\n🏃 Running Math Engine Tests...")
    math_runner = MathRunner()
    for test in math_suite:
        print(f"  - Testing {test['id']} ({test['difficulty']})...")
        await math_runner.run_test(test)
    
    math_runner.save_results()
    
    # 3. Generate Safety Suite
    print("\n🛡️ Generating Safety Tests...")
    from benchmarks.deep_suite.generators.safety_generator import SafetyGenerator
    safety_gen = SafetyGenerator()
    safety_suite = safety_gen.generate_suite(count_per_level=3)
    print(f"Generated {len(safety_suite)} safety tests.")
    
    # 4. Run Safety Runner
    print("\n🏃 Running Safety Engine Tests...")
    from benchmarks.deep_suite.runners.safety_runner import SafetyRunner
    safety_runner = SafetyRunner()
    for test in safety_suite:
        print(f"  - Testing {test['id']} ({test['difficulty']})...")
        await safety_runner.run_test(test)
        
    safety_runner.save_results()
    
    # 5. Generate Logic Suite
    print("\n🧠 Generating Logic Problems...")
    from benchmarks.deep_suite.generators.logic_generator import LogicGenerator
    logic_gen = LogicGenerator()
    logic_suite = logic_gen.generate_suite(count_per_level=3)
    print(f"Generated {len(logic_suite)} logic problems.")
    
    # 6. Run Logic Runner
    print("\n🏃 Running Logic Engine Tests...")
    from benchmarks.deep_suite.runners.logic_runner import LogicRunner
    logic_runner = LogicRunner()
    for test in logic_suite:
        print(f"  - Testing {test['id']} ({test['difficulty']})...")
        await logic_runner.run_test(test)
        
    logic_runner.save_results()
    
    # 7. Generate Data Engine Suite (SQL/Stats/Fact)
    print("\n📊 Generating Data Engine Problems (SQL/Stats/Fact)...")
    from benchmarks.deep_suite.generators.data_generator import DataEngineGenerator
    data_gen = DataEngineGenerator()
    data_suite = data_gen.generate_suite(count_per_level=2)  # Smaller count
    print(f"Generated {len(data_suite)} data engine problems.")
    
    # 8. Run Data Engine Runner
    print("\n🏃 Running Data Engine Tests...")
    from benchmarks.deep_suite.runners.data_runner import DataEngineRunner
    data_runner = DataEngineRunner()
    for test in data_suite:
        print(f"  - Testing {test['id']} ({test['engine']}/{test['difficulty']})...")
        await data_runner.run_test(test)
        
    data_runner.save_results()
    
    # 9. Generate Report
    print("\n📝 Generating Report...")
    reporter = DeepReporter()
    reporter.generate_report()

if __name__ == "__main__":
    asyncio.run(main())
