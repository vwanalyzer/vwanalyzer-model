# VWAnalyzer Model

This repository contains the source codes for the VWAnalyzer framework. The detail of the design is described in our ASIA CCS '22 paper

**Hyunwoo Lee, Imtiaz Karim, Ninghui Li, and Elisa Bertino, "VWAnalyzer: A Systematic Security Analysis Framework for the Voice over WiFi Protocol." Proceedings of the 2022 ACM on Asia Conference on Computer and Communications Security. 2022.,**

which can be found at:
https://dl.acm.org/doi/abs/10.1145/3488932.3517425

The VWAnalyzer framework is to analyze the VoWiFi protocol based on its specifications and consists of two steps called _Scenario Construction_ and _Scenario Verification_.

To get the counterexamples,

1) In the scenario_construction directory,
  - Run `python3 threat_instrumented_scenario_generator.py`
  - You will find the generated scenarios under the scenario_verification directory

2) In the scenario_verification directory,
  - Run `python3 scenario_checker.py`
  - The counterexamples will be logged in the result.log file

If you want to run this verification step with your own property file,
  - Run `python3 scenario_checker.py -p <property file>`
