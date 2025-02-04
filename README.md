# Terrorism Analysis System using Neo4j

I've built a system to analyze terrorism incidents using Neo4j as my database, inspired by email-chain analysis patterns from the Panama Papers investigation. While the original task involved analyzing email communications, I am using similar query patterns to track terrorist activities and their connections.

My Python interface makes it easy to analyze patterns like:
- Tracking incident chains (similar to email chains) between different terrorist groups
- Finding common connections between different terrorist organizations
- Analyzing temporal patterns (e.g., frequency of attacks in specific time windows)
- Identifying groups that are transitively connected through joint operations
- Discovering high-frequency interaction patterns between specific groups

I've wrapped all the Neo4j database operations in a nice interface, so I don't have to write raw database queries every time I want to analyze the data. Each incident is stored as a node in the graph database with details like where it happened, when it occurred, who did it, and how many people were affected.

## Downloading the dataset

The dataset is available at https://www.kaggle.com/datasets/START-UMD/gtd # TODO: Clean the dataset. OpenRefine didn't work.

## Setup

To setup the Neo4j container, run `setup_neo4j_container.sh`.

# Usage 

To run the query, run `query.py`.

# References:

1. https://github.com/Anto188bas/TemporalMultiGraphMatch
2. https://arxiv.org/pdf/2501.09736


# **Action Items**

- the code can identify geographical overlaps through find_transitive_connections(), but that's about it. I'll be writing more queries for both temporal and not.
- The code I pushed provides two main ways to analyze regional patterns:  
    1. find_transitive_connections() - This identifies groups operating in the same regions as a target group, returning potential collaborations
    2. find_cross_region_groups() - This detects groups carrying out attacks across multiple regions within a set timeframe, showing operational shifts, and expansion.
- With Panama the team had some queries that were path queries but in a limited time (e.g. did this agent communicate perhaps through intermediaries with this other agent but in a limited time frame). Such data may not be directly available to us but maybe I can infer communication through similar modus operandi?
