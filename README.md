# Artifact Evaluation Submission for RUDRA [SOSP '21]

**Paper**: RUDRA: Finding Memory Safety Bugs in Rust at the Ecosystem Scale

## Overview

Directory structure:

```
📦 Rudra-Artifacts
┣ 📄 paper (The paper and abstract as accepted to SOSP)
```

## Getting Started

You will need the following to evaluate Rudra:

* [Docker](https://www.docker.com/)
* At least 31GB of disk space if running on all crates.io packages.

Download times in steps are based on a gigabit internet connection.


## Installing the Artifact (X human-minutes + XX compute-minutes)

### Tutorial on Using Rudra

This is a basic guide on how to run Rudra on Rust packages.


## Validating Bugs from Paper (XX human-minutes + XX compute-minutes)


## Validating Evaluation on crates.io Packages (XX human-minutes + XX compute-hours)


## Re-using Rudra Beyond the Paper (30 human-minutes)

Rudra's code can be used as an extensible framework for future research for
ecosystem or package level analysis. In particular, Rudra allows new bug finding
algorithms to be integrated easily, taking full advantage of the reporting
mechanism.

The following tutorial guides the user through the creation of a bug finding
algorithm that flags usages of the function `crash_me("please")` across all
Rust code.
