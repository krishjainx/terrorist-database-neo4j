# Terrorism Analysis System using Neo4j

I've built a system to analyze terrorism incidents using Neo4j as my database, inspired by email-chain analysis patterns from the Panama Papers investigation. While the original task involved analyzing email communications, I am using similar query patterns to track terrorist activities and their connections.

My Python interface makes it easy to analyze patterns like:
- Tracking incident chains (similar to email chains) between different terrorist groups
- Finding common connections between different terrorist organizations
- Analyzing temporal patterns (e.g., frequency of attacks in specific time windows)
- Identifying groups that are transitively connected through joint operations
- Discovering high-frequency interaction patterns between specific groups

I've wrapped all the Neo4j database operations in a nice interface, so I don't have to write raw database queries every time I want to analyze the data. Each incident is stored as a node in the graph database with details like where it happened, when it occurred, who did it, and how many people were affected.

