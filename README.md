# IntSight

IntSight Prototype for Mininet + BMv2.

## Environment Setup

Install the P4 development and testing tools following the scripts in our [P4 tutorials repository fork](https://github.com/jonadmark/tutorials/tree/master/vm). Make sure to install the tools using the same commit versions as defined in the repository (script: `vm/user-bootstrap.sh`)

In addition to the dependencies listed on the scripts mentioned above, the experiment suite requires the following packages.
- [NetworkX](https://networkx.github.io/documentation/stable/install.html) for Python3
- [Scapy](https://scapy.net/download/) for Python3
- [tcpreplay](https://tcpreplay.appneta.com/wiki/installation.html)

Note: For best performance, it is strongly recommended to setup the P4 environment on a baremetal machine (as opposed to a virtual machine).

The evaluation notebooks rely on [Jupyter Notebooks](https://jupyter.org/install) along with the following Python3 dependencies:
- [NumPy](https://numpy.org/install/)
- [Pandas](https://pandas.pydata.org/getting_started.html)
- [MatPlotLib](https://matplotlib.org/users/installing.html)

Note: We recommend installing all Python dependencies using the [Conda](https://docs.conda.io/en/latest/miniconda.html) package, dependency and environment management tool.

## IntSight Setup

It is recommended to clone this repository inside an empty directory. The workload files are generated on a separated subdirectory inside the main directory where this repository is cloned into.

## IntSight Experiments

Experiments are defined and configured inside the `experiments` directory. A `network.json` file defines the network topology, workload definition file, flow SLOs, and other minor parameters. A `workload.json` file defines the workload to be executed during the experiment. A `genpcaps.py` script defines a recipe for generating the pcaps used by tcpreplay to generate the workload as defined in `workload.json`. Run every experiment `genpcaps.py` script to generate their base workload files. The `paper_results` directory contains all the results for that particular experiment that were publish in the paper. A `jupyter.ipynb` file represents the Jupyter notebook used to generate the figures out of experimental results.

## Running an Experiment

To run a experiment, simply execute the `experiment.sh` script passing one of the previously defined experiments as the single parameter. For example, to run the `e2edelay` experiment, run the following command:

```
bash experiment.sh experiments/e2edelay/network.json
```

Similarly, to run the `bandwidth` experiment, run the following command:

```
bash experiment.sh experiments/bandwidth/network.json
```

When the experiment is finished, the generated reports are available inside the main `logs` directory. A pair of files is created for the reports of each node in the network (e.g., `s1-reports.txt` and `s1-reports.csv`). The txt file is a human-readable version of the reports, the csv file is generated to help with automated evaluation scripts.
