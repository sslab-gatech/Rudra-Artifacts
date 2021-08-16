# Artifact Evaluation Submission for RUDRA [SOSP '21]

**Paper**: RUDRA: Finding Memory Safety Bugs in Rust at the Ecosystem Scale


## Overview

Directory structure:

```
📦 Rudra-Artifacts
┣ 📄 paper (The paper and abstract as accepted to SOSP)
```

### Inputs/Outputs

Rudra itself is an analyzer that takes Rust packages (crates) as inputs and
outputs reports from the findings of bug-finding algorithms. As an example,
here is a screenshot of a Rust package containing a bug and its corresponding
report generated by Rudra.

## Getting Started & Basic Usage

You will need the following to evaluate Rudra:

* [Docker](https://www.docker.com/)
* Python 3
* [Rust Toolchain](https://www.rust-lang.org/tools/install) and [cargo-download](https://crates.io/crates/cargo-download)
* git
* About 40 GB of disk space if running on all crates.io packages.

Download times in steps are based on a gigabit internet connection.

## Installing the Artifact (X human-minutes + XX compute-minutes)

This guide describes how to use Rudra with Docker on Linux environment.

1. Install [Docker](https://docs.docker.com/get-docker/) and Python 3 on your system.
1. Install [Rust Toolchain](https://www.rust-lang.org/tools/install).
    * The recommended way is to use rustup.
        * `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
    * You might need to restart your shell, so that `$HOME/.cargo/bin` is in the `$PATH`.
    * Any recent stable version should work since it is only used for `cargo-download`.
1. Install [cargo-download](https://crates.io/crates/cargo-download).
    * Run `cargo install cargo-download` after setting up the Rust toolchain.
    * This command lets us download crates (Rust packages) from Rust's official registry [crates.io](https://crates.io/).
1. Clone [Rudra](https://github.com/sslab-gatech/Rudra) and [Rudra-Artifact](https://github.com/sslab-gatech/Rudra-Artifacts) repositories.
1. In Rudra repository, run `docker build . -t rudra:latest`.
1. In Rudra repository, run `./setup_rudra_runner_home_fixed.py <directory>` and set `RUDRA_RUNNER_HOME` to that directory.
    * Example: `./setup_rudra_runner_home_fixed.py ~/rudra-home && export RUDRA_RUNNER_HOME=$HOME/rudra-home`
    * Note: DO NOT run `./setup_rudra_runner_home.py`
1. Add `docker-helper` in Rudra repository to `$PATH`. Now you are ready to test Rudra!

## Basic Usability Test: Running Rudra on a single project (XX human-minutes + XX compute-minutes)

```
docker-cargo-rudra <directory>
```

The log and report are printed to stderr by default.

TODO: choose an example project and describe the expected output

## Validating Bugs from Paper (XX human-minutes + XX compute-minutes)

TODO: update test scripts to use Docker-based Rudra (rudra-poc/paper/recreate_bugs.py)

## Validating Rust standard library bugs (10 human-minutes + 30 compute-minutes)

Analyzing the Rust standard library and compiler is slightly different than a
simple Rust package. We have included a Docker image that will perform all the
steps to do the analysis.

1. Install [Docker](https://docs.docker.com/get-docker/) and set up the `rudra`
   image as explained in the *Installing the Artifact* section above.
1. Change into the `rudra/stdlib-analysis` directory.
1. Build the standard library analysis image with: `docker build -t rudra-std .`
1. Run the analysis on the standard library and pipe the reports into a file:
   `docker run -it rudra-std > rudra-std-report.txt`

The generated `rudra-std-report.txt` file should contain Rudra's output and
reports which can be used to verify the claims about Rust standard library
and compiler bugs identified in the paper.

The next few sections show the claimed bugs from the different parts of the
paper. The final section shows how to correlate them with Rudra's bug reports.

### Abstract

> The new bugs RUDRA found are nontrivial and subtle and often made by Rust
> experts: two in the std library, ... and one in the Rust compiler, rustc.

Claimed: RUDRA-STD-1, RUDRA-STD-2, RUDRA-RUSTC-1

### 1. Introduction

> these memory safety bugs are subtle and non-trivial, e.g., two in the standard
> library, ... and one in the Rust compiler, rustc, which are the mistakes made
> by Rust experts.

Claimed: RUDRA-STD-1, RUDRA-STD-2, RUDRA-RUSTC-1

### Figure 3

> An example of a panic safety bug, fix, and PoC in the Rust standard library
> that RUDRA found (CVE-2020-36317).
> It was independently fixed, but the latest stable version was still vulnerable
> when RUDRA discovered it.

Claimed: RUDRA-STD-3 (Independently Fixed)

### 3.2 Higher-order Safety Invariant

> This bug in the `join()` function for `[Borrow<str>]` was discovered by RUDRA
> in the Rust standard library.

Claimed: RUDRA-STD-1

### Figure 4

> A missing check of the higher-order invariant introduces a time-of-check to
> time-of-use bug in the Rust standard library (`join()` for `[Borrow<str>]`).
> RUDRA found this previously unknown bug (CVE-2020-36323).

Claimed: RUDRA-STD-1

### Table 4

> | Package | Location              | ... | Bug ID                    |
> |---------|-----------------------|-----|---------------------------|
> | std     | str.rs <br/> mod.rs   | ... | C20-36323 <br/> C21-28875 |
> | rustc   | worker_local.rs       | ... | rust#81425                |

Claimed: RUDRA-STD-1, RUDRA-STD-2, RUDRA-RUSTC-1

### Correlating with RUDRA's Reports

These are the claimed bugs from the paper above, their descriptions and bug
reports as well as the RUDRA reports that identified them. The reports should
be present in the `rudra-std-report.txt` file generated above.

#### RUDRA-STD-1

```
Info (UnsafeDataflow:/SliceUnchecked): Potential unsafe dataflow issue in `str::join_generic_copy`
-> /usr/local/rustup/toolchains/nightly-2020-08-26-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/alloc/src/str.rs:137:1: 182:2
```

`join` on `[Borrow<str>]` can return uninitialized memory if the borrowed
string returns different strings as part of the `Borrow` trait.
[[CVE-2020-36323](https://nvd.nist.gov/vuln/detail/CVE-2020-36323)]
[[rust-lang/rust#80335](https://github.com/rust-lang/rust/issues/80335)]

#### RUDRA-STD-2

```
Info (UnsafeDataflow:/VecSetLen): Potential unsafe dataflow issue in `io::read_to_end_with_reservation`
-> /usr/local/rustup/toolchains/nightly-2020-08-26-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/std/src/io/mod.rs:354:1: 399:2
```

A `Read` implementation that returns a bytes read larger than the buffer size,
calling `read_to_end` and `read_to_string` can cause a heap buffer overflow.
[[CVE-2021-28875](https://nvd.nist.gov/vuln/detail/CVE-2021-28875)]
[[rust-lang/rust#80894](https://github.com/rust-lang/rust/issues/80894)]

#### RUDRA-STD-3 (Independently Fixed)

```
Info (UnsafeDataflow:/CopyFlow): Potential unsafe dataflow issue in `string::String::retain`
-> /usr/local/rustup/toolchains/nightly-2020-08-26-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/alloc/src/string.rs:1230:5: 1263:6
```

When `String::retain()` is provided with a filter function `f` that can panic,
the string can end up containing non-UTF-8 encoded bytes. This breaks the
standard library's assumption that strings are UTF-8 encoded and can lead to
memory safety issues.
[[CVE-2020-36317](https://nvd.nist.gov/vuln/detail/CVE-2020-36317)]
[[rust-lang/rust#78498](https://github.com/rust-lang/rust/issues/78498)]

#### RUDRA-RUSTC-1

```
Info (SendSyncVariance:/PhantomSendForSend/NaiveSendForSend/RelaxSend): Suspicious impl of `Send` found
-> rayon-core/src/worker_local.rs:18:1: 18:42
unsafe impl<T> Send for WorkerLocal<T> {}
Info (SendSyncVariance:/ApiSyncforSync/NaiveSyncForSync/RelaxSync): Suspicious impl of `Sync` found
-> rayon-core/src/worker_local.rs:19:1: 19:42
unsafe impl<T> Sync for WorkerLocal<T> {}
```

The `WorkerLocal` struct used in parallel compilation mode could lead to data
races across threads.
[[rust-lang/rust#81425](https://github.com/rust-lang/rust/issues/81425)]



## Validating Evaluation on crates.io Packages (XX human-minutes + XX compute-hours)

First, download `rudra_runner_home-cached.tar.gz` from TODO and unpack it to `$RUDRA_RUNNER_HOME`.
Then, you can run Rudra on all crates published on crates.io with the following command.

```
docker-rudra-runner
```

This step took 6.5 hours on a machine with 32-core AMD EPYC 7452, 252 GB memory, and an NVMe SSD that runs Ubuntu 20.04.
The analysis result will be saved in `$RUDRA_RUNNER_HOME/campaign/YYYYMMDD_HHmmss/[log|report]` directories.

TODO: explain how to use our log analysis scripts to verify the result (rudra-poc/paper/log_analyzer.py)

## Re-using Rudra Beyond the Paper (30 human-minutes)

Rudra's code can be used as an extensible framework for future research for
ecosystem or package level analysis. In particular, Rudra allows new bug finding
algorithms to be integrated easily, taking full advantage of the reporting
mechanism.

The following tutorial guides the user through the creation of a bug finding
algorithm that flags usages of the function `crash_me("please")` across all
Rust code.
