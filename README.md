# IntSight

IntSight Prototype for Mininet + BMv2.

# Environment Setup

Install P4 tools following the scripts in [P4 tutorials repository fork](https://github.com/jonadmark/tutorials/tree/master/vm). Make sure to install the tools using the same commit versions as defined on the repository.

In addition to the dependencies listed on the scripts mentioned above, the experiment suite requires the following packages.
- [python-networkx](https://networkx.github.io/documentation/stable/install.html)
- [tcpreplay](https://tcpreplay.appneta.com/wiki/installation.html)

Note: For best performance, it is strongly recommended to setup the P4 environment on a baremetal machine (as opposed to a virtual machine).

# IntSight Experiments

Experiments are defined and configured inside the `experiments` directory. A `network.json` file defines the network topology, workload definition file, flow SLOs, and other minor parameters. A `workload.json` file defines the workload to be executed during the experiment. A `genpcaps.py` script defines a recipe for generating the pcaps used by tcpreplay to generate the workload as defined in `workload.json`.

# Running an Experiment

To run a experiment, simply execute the `experiment.sh` script passing one of the previously defined experiments as the single parameter. For example, to run the `e2edelay` experiment, run the following command:

```
bash experiment.sh experiments/e2edelay/network.json
```

Similarly, to run the `bandwidth` experiment, run the following command:

```
bash experiment.sh experiments/bandwidth/network.json
```

When the experiment is finished, the generated reports are available inside the `logs` directory. A pair of files is created for the reports of each node in the network (e.g., `s1-reports.txt` and `s1-reports.csv`). The txt file is a human-readable version of the reports, the csv file is generated to help with automated evaluation scripts.
