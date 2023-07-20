# Bachelor's Thesis: Analysis of authoritative DNS infrastructure failures

This repository contains the research work conducted for the Bachelor's thesis titled "Analysis of authoritative DNS infrastructure failures." The study focuses on examining the effects of failures in authoritative DNS servers on the overall performance and resilience of the DNS system. The experiments conducted in this research aim to provide insights into how the DNS system can defend itself against such failures and maintain its functionality.

## Overview

In this thesis, we investigate the implications of failures in authoritative DNS servers and analyze the resilience of the DNS system in the face of these failures. To achieve this, we created a controlled environment where we had complete control over an authoritative name server and a DNS client. Public resolvers from various DNS operators were used to simulate real-world scenarios and perform experiments.

## Repository Contents

This repository contains the following resources:

1. **Thesis**: The complete written thesis document outlining the research methodology, experimental setup, analysis of results, and conclusions.

2. **Experiment Scripts**: The scripts developed for conducting the experiments in the controlled environment. These scripts are available for reference and replication of the research.

3. **Experiment Logs**: Detailed logs of the experiments conducted, including configurations, inputs, outputs, and relevant metrics.

4. **Plots**: Graphical representations of the experiment logs, illustrating the measured metrics such as resolution success rate, resolution latency, stale records, and the number of DNS retransmissions.

## Key Findings

The research findings highlight the following key observations:

- Despite failures in authoritative DNS servers, the DNS system demonstrates robustness and the ability to handle disruptions effectively. A resolver can be configured to implement mechanisms such as utilizing dns retransmissions, caching and stale records to be more robust against authoritative server failures. 

- When a dns resolver is able to utilize stale records, the resolution success rate remains relatively high even in the presence of partial or complete failures in authoritative servers.

- Resolution latency experiences a slight increase during failure scenarios but generally remains within an acceptable range, when the resolution succeeds. The latency is also affected by the amount of dns retransmissions that a resolver is configured to send.

- While the amount of dns retransmissions made by the resolver may increase the resolution latency, it also lowers the rate of failed dns queries.

- Sending too many dns retransmissions may contribute to a DDoS attack by increasing the traffic of the already overloaded server. The servers might adjust the retransmission amounts dynamically if they detect an unusual network traffic.

## Contact Information

For any inquiries or further information regarding this research work, please feel free to reach out to the author:

- [Ege Girit]
- [egegirit@gmail.com]

I appreciate any feedback, suggestions, or collaborations related to this research.

## License

The contents of this repository are available under the [MIT License](LICENSE).
