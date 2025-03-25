# Benchmarks

This subproject contains benchmark implement and scripts to generate benchmarks from the command line.

## To benchmark

There are two sets of scrips, those prefixed with "arm_xxx" will benchmark the arm related variant and the non prefixed
scripts, for example "benchmark_linux_cbc.sh" will benchmark the intel related variants.

### To run a script:

#### Basic set up
First ensure the bc-lts-java-jars is checked out at the same level as the bc-lts-java project, for example:

```
<path to>/
    bc-lts-java
    bc-lts-java-jars
```

Change into ```<path to>/bc-lts-java/benchmark```

#### Java Version
This build uses gradle 8.13.x you will need to have Java21 + on your path to run a build because it needs
to produce JDK21 code.

For example:

```
java -version

openjdk version "21" 2023-09-19
OpenJDK Runtime Environment Zulu21.28+85-CA (build 21+35)
OpenJDK 64-Bit Server VM Zulu21.28+85-CA (build 21+35, mixed mode, sharing)

```

#### Run a benchmark

To create a benchmark and associated graph for a particular transformation run the appropriate script:

For example, CBC on Intel:

```
    #
    # select the script supplying the library version of interest as the first argument
    #
    
    benchmark$ ./benchmark_linux_cbc.sh 2.73.7
```

In the above example note the version of the LTS library, to find versions look in:

```
# Assuming you are in the benchmark dir:

ls -al ../../bc-lts-java-jars/

```

