# Academic References & Prior Work

This benchmark and detection suite grounds its indirect prompt injection taxonomy and evaluation metrics in peer-reviewed security and adversarial machine learning literature.

---

## Primary Literature

### 1. Indirect Prompt Injection (Foundational Paper)
> **Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection**  
> *Kai Greshake, Sahar Abdelnabi, Shailesh Mishra, Christoph Endres, Thorsten Holz, Mario Fritz*  
> **ACM Workshop on Artificial Intelligence and Security (AISec / CCS)**, 2023.  
> [arXiv:2302.12173](https://arxiv.org/abs/2302.12173)
```bibtex
@inproceedings{greshake2023not,
  title={Not what you've signed up for: Compromising real-world LLM-integrated applications with indirect prompt injection},
  author={Greshake, Kai and Abdelnabi, Sahar and Mishra, Shailesh and Endres, Christoph and Holz, Thorsten and Fritz, Mario},
  booktitle={Proceedings of the 16th ACM Workshop on Artificial Intelligence and Security},
  pages={79--90},
  year={2023}
}
```

### 2. Jailbreak Mechanisms & Safety Training Failure Modes
> **Jailbroken: How Does LLM Safety Training Fail?**  
> *Alexander Wei, Nika Haghtalab, Jacob Steinhardt*  
> **NeurIPS**, 2023.  
> [arXiv:2307.02483](https://arxiv.org/abs/2307.02483)
```bibtex
@inproceedings{wei2023jailbroken,
  title={Jailbroken: How Does LLM Safety Training Fail?},
  author={Wei, Alexander and Haghtalab, Nika and Steinhardt, Jacob},
  booktitle={Thirty-seventh Conference on Neural Information Processing Systems},
  year={2023}
}
```

### 3. Adversarial Suffixes & Optimization Attacks
> **Universal and Transferable Adversarial Attacks on Aligned Language Models**  
> *Andy Zou, Zifan Wang, J. Zico Kolter, Matt Fredrikson*  
> **arXiv preprint**, 2023.  
> [arXiv:2307.15043](https://arxiv.org/abs/2307.15043)
```bibtex
@article{zou2023universal,
  title={Universal and transferable adversarial attacks on aligned language models},
  author={Zou, Andy and Wang, Zifan and Kolter, J Zico and Fredrikson, Matt},
  journal={arXiv preprint arXiv:2307.15043},
  year={2023}
}
```

### 4. Non-Parametric Bootstrap Confidence Estimation
> **Bootstrap Methods: Another Look at the Jackknife**  
> *Bradley Efron*  
> **The Annals of Statistics**, 1979.  
> [DOI:10.1214/aos/1176344552](https://doi.org/10.1214/aos/1176344552)
```bibtex
@article{efron1979bootstrap,
  title={Bootstrap methods: another look at the jackknife},
  author={Efron, Bradley},
  journal={The Annals of Statistics},
  volume={7},
  number={1},
  pages={1--26},
  year={1979}
}
```

---

## Industry Frameworks
- **OWASP Top 10 for LLM Applications (2025)**: Control `LLM01: Prompt Injection` (Direct and Indirect Prompt Injections).
- **MITRE ATLAS (Adversarial Threat Landscape for AI Systems)**: Technique `AML.T0051: LLM Prompt Injection`.
