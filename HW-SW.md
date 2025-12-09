# Evaluating New Hardware-Software Codesigned Defenses

Researchers can reuse Protean's security evaluation infrastructure 
to evaluate the security of their own hardware-software codesigned Spectre
defenses that are similarly implemented for gem5 and LLVM
as follows.

1. Repoint the variable `llvm_dir` in [src/generator_llvm.py](src/generator_llvm.py) to point to the directory containing your built LLVM binaries, such as `llc` and `opt`.
2. Copy our `llvm-stress` binary, which generates random input LLVM-IR programs, into your LLVM binary directory (AMuLeT* looks in `llvm_dir` for it).
3. Add your gem5 model (e.g., `mydefense`) as a subdirectory in `gem5/` (e.g., `gem5/mydefense`). 
4. Merge in changes we made to the unsafe baseline and build your gem5 model: 
```
cd gem5/mydefense
git remote add protean-amulet https://github.com/StanfordPLArchSec/protean-gem5.git
git merge protean-amulet/amulet/base
scons build/X86/gem5.opt
```
5. Add your defense to the `defenses` list in [Snakefile](Snakefile). It might look like:
```python
defenses.append(
    Defense(
        name = "mydefense",
		gem5_dir = "gem5/mydefense",
		script_opts = [... your defenses' se.py script options ...],
    )
)
```
6. Name your defense's compiler flags in `get_generator()` in [src/generator.py](src/generator.py) (e.g., "llvm.mycc"). 
6. Start fuzzing with Snakemake (where "contract" is some relevant contract like ct, cts, arch):
```shell
snakemake --cores=all mydefense-contract-llvm.mycc-cache/all
```
