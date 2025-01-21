#!/usr/bin/env python3

from neo4j import GraphDatabase

class Neo4jTerrorismDB:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def run_query(self, query, parameters=None):
        with self.driver.session() as session:
            result = session.run(query, parameters)
            return [record.data() for record in result]

    def get_group_activities_in_timerange(self, group_name, start_date, end_date):
        """Get activities by a group in a specific date range."""
        query = """
        MATCH (i:Incident)
        WHERE i.gname = $group_name
        AND date({year: i.iyear, month: coalesce(i.imonth, 1), day: coalesce(i.iday, 1)}) >= date($start_date)
        AND date({year: i.iyear, month: coalesce(i.imonth, 1), day: coalesce(i.iday, 1)}) <= date($end_date)
        RETURN i.eventid AS EventID, i.city AS City,
               date({year: i.iyear, month: coalesce(i.imonth, 1), day: coalesce(i.iday, 1)}) AS Date,
               i.attacktype1_txt AS AttackType, i.target1 AS Target, i.nkill AS Casualties,
               i.nwound AS Wounded, i.country_txt AS Country
        ORDER BY Date
        """
        return self.run_query(query, {
            "group_name": group_name,
            "start_date": start_date,
            "end_date": end_date
        })

    def high_frequency_attacks(self, group_name, hours_interval=4, min_attacks=10):
        """Find periods of high-frequency attacks by a group."""
        query = """
        MATCH (i:Incident)
        WHERE i.gname = $group_name
        WITH date({year: i.iyear, month: coalesce(i.imonth, 1), day: coalesce(i.iday, 1)}) AS attack_date,
             i.city AS location
        WITH attack_date, collect(location) AS locations, count(*) AS AttackCount
        WHERE AttackCount >= $min_attacks
        RETURN attack_date AS Date, AttackCount, locations AS Locations
        ORDER BY attack_date
        """
        return self.run_query(query, {
            "group_name": group_name,
            "hours": hours_interval,
            "min_attacks": min_attacks
        })

    def find_attack_chain(self, start_group, end_group, max_length=None):
        """Find attack chains linking two groups."""
        length_constraint = f"AND length(path) <= {max_length}" if max_length else ""
        query = f"""
        MATCH path = (start:Incident)-[:RELATED_TO*]->(end:Incident)
        WHERE start.gname = $start_group AND end.gname = $end_group
        {length_constraint}
        RETURN [incident IN nodes(path) | 
                {{group: incident.gname, date: date({{year: incident.iyear, month: coalesce(incident.imonth, 1), day: coalesce(incident.iday, 1)}}), location: incident.city, casualties: incident.nkill}}
        ] AS chain
        ORDER BY length(path)
        LIMIT 5
        """
        return self.run_query(query, {
            "start_group": start_group,
            "end_group": end_group
        })

    def find_transitive_connections(self, group_name, days=4):
        """Find transitive connections to a group over the last X days."""
        query = """
        MATCH path = (i1:Incident)-[:RELATED_TO*]->(target:Incident)
        WHERE target.gname = $group_name
        AND duration.inDays(
            date({year: i1.iyear, month: coalesce(i1.imonth, 1), day: coalesce(i1.iday, 1)}),
            date({year: target.iyear, month: coalesce(target.imonth, 1), day: coalesce(target.iday, 1)})
        ) <= $days
        RETURN DISTINCT i1.gname AS ConnectedGroup, COUNT(path) AS ConnectionCount
        ORDER BY ConnectionCount DESC
        """
        return self.run_query(query, {
            "group_name": group_name,
            "days": days
        })

if __name__ == "__main__":
    db = Neo4jTerrorismDB("bolt://localhost:7687", "neo4j", "password")

    try:
        # Query 1: Group activities in a date range
        print("1. Taliban activities in 2015:")
        activities = db.get_group_activities_in_timerange("Taliban", "2015-01-01", "2015-12-31")
        for activity in activities:
            print(activity)

        # Query 2: High-frequency attack periods
        print("\n2. High-frequency attack periods by Taliban:")
        high_freq = db.high_frequency_attacks("Taliban", hours_interval=4, min_attacks=10)
        for period in high_freq:
            print(period)

        # Query 3: Attack chains between groups
        print("\n3. Attack chains between Taliban and ISIS:")
        chains = db.find_attack_chain("Taliban", "Islamic State of Iraq and the Levant (ISIL)", max_length=5)
        for chain in chains:
            print(chain)

        # Query 4: Transitive connections
        print("\n4. Transitive connections to ISIS over 7 days:")
        connections = db.find_transitive_connections("Islamic State of Iraq and the Levant (ISIL)", days=7)
        for connection in connections:
            print(connection)

    finally:
        db.close()
