from skills_scanner import SkillScanner

scanner = SkillScanner(use_agent=False)
report = scanner.scan(
    target="https://swarms.world/prompt/32d1e7b4-34da-4035-bc05-d18f8e71a2f1.md"
)

print(report.to_json())
