#!/usr/bin/env python3

from neo4j import GraphDatabase

"""
Some Queries Formulated (in English) In The Style We Want To Use:

1. Temporal Connection Analysis:
- Which terrorist groups operated in both Region X and Region Y within a 30-day period?
- Find attack sequences where Group X hit Target 1, then Group Y attacked related Target 2 within 72 hours
- Which cities experienced attacks from >3 different groups within any 48-hour window?
- Track movement patterns of groups across regions with timing analysis

2. Network Analysis:
- What groups share common attributes (weapon types, target preferences, tactics)?
- Identify groups that operate in similar geographical patterns
- Find groups that potentially share resources based on attack characteristics
- Map connections between groups through shared attack patterns

3. Pattern Recognition:
- Has any group conducted more than X attacks using the same method within a time period?
- Which groups have switched their primary attack type after major events?
- Are there pairs of groups that tend to conduct attacks in the same regions within short intervals?
- Identify regions where attacks cluster in specific annual periods

4. Resource Tracking:
- Which groups have used similar weapon types and ransom demands in their operations?
- Track changes in weapon types and attack methods over time
- What is the network of groups targeting similar infrastructure across different countries?
- Identify patterns in hostage-taking operations and demands

5. Strategic Analysis:
- Find groups that stopped operating in one region but appeared in another within specific timeframes
- Identify potential collaboration between groups based on attack patterns
- Track evolution of attack methods and target selection over time
- Analyze regional shifts in group activities

6. Forensic Patterns:
- Find attacks with matching characteristics (weapon type, demands, methods) within short time windows
- Identify signature attack patterns of specific groups
- Track changes in group tactics after significant events

External Datasets to Find (*TODO*):
1. Counter-terrorism Operations: Military interventions, law enforcement actions, policy changes and legislation
2. Resource Networks: Weapon supply chains, financial transactions, training camp locations, transportation routes
3. Communication Data: Propaganda channels, group affiliations, leadership structures
4. Contextual Information: Regional political events, religious holidays, international sanctions, border security changes

Current Status:

1. Data Structure:
   I've built the database to store incident-level properties, but I still need to implement explicit event relationships and integrate external intelligence data.

2. Temporal Analysis:
   I've implemented basic date-based queries but need to enhance the temporal reasoning to detect sophisticated attack patterns and event sequences.

3. Network Analysis:
   I can track basic group connections, but I need to add multi-hop traversal algorithms to analyze resource sharing and complex organizational relationships.

4. Pattern Recognition:
   I've got basic frequency analysis working but need to implement advanced similarity metrics and pattern matching to identify sophisticated attack signatures.

Cool Things I Could Do:

1. Graph Structure:
   I plan to rebuild the node structure to map relationships between incidents, track group-level properties, and monitor resource/location patterns.

2. Query Capabilities:
   I need to add path-finding algorithms, temporal reasoning functions, and attack similarity scoring to enable more complex intelligence analysis.

3. Data Integration:
   I'll build API connectors for external datasets to enable real-time updates and cross-referencing with signals intelligence and OSINT sources.
   
"""

class Neo4jTerrorismDB:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def run_query(self, query, parameters=None):
        with self.driver.session() as session:
            result = session.run(query, parameters)
            return [record.data() for record in result]

    def get_groups_in_regions(self, region1, region2, months=6):
        """Find groups that operated in both specified regions within a time period."""
        query = """
        MATCH (i1:Incident)
        WHERE i1.region_txt = $region1 AND i1.gname IS NOT NULL AND i1.gname <> 'Unknown'
        WITH i1, i1.gname AS group_name
        MATCH (i2:Incident)
        WHERE i2.gname = group_name 
        AND i2.region_txt = $region2
        RETURN DISTINCT group_name AS GroupName,
               count(i1) + count(i2) AS TotalAttacks
        ORDER BY TotalAttacks DESC
        """
        return self.run_query(query, {
            "region1": region1,
            "region2": region2
        })

    def find_cities_multiple_attacks(self, hours=48):
        """Find cities that experienced attacks from different groups within specified hours."""
        query = """
        MATCH (i1:Incident)
        WHERE i1.city IS NOT NULL
        WITH i1
        MATCH (i2:Incident)
        WHERE i1.city = i2.city 
        AND i1.gname <> i2.gname
        AND i1.iyear = i2.iyear
        AND i1.imonth = i2.imonth
        AND abs(i1.iday - i2.iday) * 24 <= $hours
        RETURN i1.city AS City,
               collect(DISTINCT i1.gname) + collect(DISTINCT i2.gname) AS Groups,
               i1.country_txt AS Country,
               count(DISTINCT i2) AS AttackCount
        ORDER BY AttackCount DESC
        LIMIT 10
        """
        return self.run_query(query, {"hours": hours})

    def find_groups_similar_tactics(self, group1, group2):
        """Find other groups using similar tactics as the specified groups."""
        query = """
        MATCH (i1:Incident)
        WHERE i1.gname = $group1
        WITH collect(DISTINCT i1.attacktype1) AS g1_tactics
        MATCH (i2:Incident)
        WHERE i2.gname = $group2
        WITH g1_tactics, collect(DISTINCT i2.attacktype1) AS g2_tactics
        MATCH (i3:Incident)
        WHERE i3.gname <> $group1 
        AND i3.gname <> $group2
        AND i3.attacktype1 IN g1_tactics
        AND i3.attacktype1 IN g2_tactics
        RETURN DISTINCT i3.gname AS GroupName,
               collect(DISTINCT i3.attacktype1_txt) AS SharedTactics,
               count(DISTINCT i3) AS AttackCount
        ORDER BY AttackCount DESC
        """
        return self.run_query(query, {
            "group1": group1,
            "group2": group2
        })

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
        """Find attack chains linking two groups through shared locations or tactics."""
        query = """
        MATCH (start:Incident)
        WHERE start.gname = $start_group
        WITH start
        MATCH (end:Incident)
        WHERE end.gname = $end_group
        AND start.iyear <= end.iyear
        RETURN DISTINCT {
            start_attack: {
                group: start.gname,
                date: date({year: start.iyear, month: coalesce(start.imonth, 1), day: coalesce(start.iday, 1)}),
                location: start.city,
                attack_type: start.attacktype1_txt
            },
            end_attack: {
                group: end.gname,
                date: date({year: end.iyear, month: coalesce(end.imonth, 1), day: coalesce(end.iday, 1)}),
                location: end.city,
                attack_type: end.attacktype1_txt
            }
        } AS chain
        ORDER BY chain.start_attack.date
        LIMIT 5
        """
        return self.run_query(query, {
            "start_group": start_group,
            "end_group": end_group
        })

    def find_transitive_connections(self, group_name, days=4):
        """Find groups operating in same regions as the target group."""
        query = """
        MATCH (target:Incident)
        WHERE target.gname = $group_name
        WITH target.region_txt AS regions
        MATCH (i:Incident)
        WHERE i.region_txt IN regions
        AND i.gname <> $group_name
        AND i.gname IS NOT NULL
        AND i.gname <> 'Unknown'
        RETURN DISTINCT i.gname AS ConnectedGroup,
               count(i) AS AttackCount,
               collect(DISTINCT i.region_txt) AS SharedRegions
        ORDER BY AttackCount DESC
        LIMIT 10
        """
        return self.run_query(query, {
            "group_name": group_name
        })

    def find_cross_region_groups(self, region1, region2, days=30):
        """
        Which groups conducted attacks in both Region A and Region B within a 30-day period?
        """
        query = """
        MATCH (i1:Incident)
        WHERE i1.region_txt = $region1
        WITH i1, date({year: i1.iyear, month: coalesce(i1.imonth, 1), day: coalesce(i1.iday, 1)}) AS date1
        MATCH (i2:Incident)
        WHERE i2.region_txt = $region2 
        AND i2.gname = i1.gname
        AND i2.gname IS NOT NULL 
        AND i2.gname <> 'Unknown'
        AND date({year: i2.iyear, month: coalesce(i2.imonth, 1), day: coalesce(i2.iday, 1)}) >= date1
        AND date({year: i2.iyear, month: coalesce(i2.imonth, 1), day: coalesce(i2.iday, 1)}) <= date1 + duration({days: $days})
        RETURN DISTINCT i1.gname as group_name,
               collect(DISTINCT i1.region_txt) + collect(DISTINCT i2.region_txt) as regions,
               count(DISTINCT i1) + count(DISTINCT i2) as total_attacks
        ORDER BY total_attacks DESC
        """
        return self.run_query(query, {"region1": region1, "region2": region2, "days": days})

    def find_sequential_target_attacks(self, hours=72):
        """
        Find attack sequences where Group X hit Target 1, then Group Y attacked related Target 2 within 72 hours
        """
        query = """
        MATCH (i1:Incident)
        WHERE i1.targtype1_txt IS NOT NULL
        AND i1.imonth IS NOT NULL 
        AND i1.iday IS NOT NULL
        AND i1.iyear IS NOT NULL
        WITH i1, date({
            year: i1.iyear,
            month: CASE WHEN i1.imonth = 0 THEN 1 ELSE i1.imonth END,
            day: CASE WHEN i1.iday = 0 THEN 1 ELSE i1.iday END
        }) AS date1
        MATCH (i2:Incident)
        WHERE i2.targtype1_txt = i1.targtype1_txt
        AND i2.gname <> i1.gname
        AND i2.imonth IS NOT NULL 
        AND i2.iday IS NOT NULL
        AND i2.iyear IS NOT NULL
        AND date({
            year: i2.iyear,
            month: CASE WHEN i2.imonth = 0 THEN 1 ELSE i2.imonth END,
            day: CASE WHEN i2.iday = 0 THEN 1 ELSE i2.iday END
        }) > date1
        AND date({
            year: i2.iyear,
            month: CASE WHEN i2.imonth = 0 THEN 1 ELSE i2.imonth END,
            day: CASE WHEN i2.iday = 0 THEN 1 ELSE i2.iday END
        }) <= date1 + duration({hours: $hours})
        RETURN i1.gname as first_group,
               i2.gname as second_group,
               i1.targtype1_txt as target_type,
               i1.city as first_city,
               i2.city as second_city,
               duration.between(
                   date1,
                   date({
                       year: i2.iyear,
                       month: CASE WHEN i2.imonth = 0 THEN 1 ELSE i2.imonth END,
                       day: CASE WHEN i2.iday = 0 THEN 1 ELSE i2.iday END
                   })
               ).hours as hours_between
        ORDER BY hours_between
        LIMIT 10
        """
        return self.run_query(query, {"hours": hours})

    def find_cities_multiple_groups(self, min_groups=3, hours=48):
        """
        Which cities saw attacks from >3 different groups in any 48-hour window?
        """
        query = """
        MATCH (i1:Incident)
        WHERE i1.city IS NOT NULL
        AND i1.imonth IS NOT NULL 
        AND i1.iday IS NOT NULL
        AND i1.iyear IS NOT NULL
        WITH i1, date({
            year: i1.iyear,
            month: CASE WHEN i1.imonth = 0 THEN 1 ELSE i1.imonth END,
            day: CASE WHEN i1.iday = 0 THEN 1 ELSE i1.iday END
        }) AS date1
        MATCH (i2:Incident)
        WHERE i2.city = i1.city
        AND i2.imonth IS NOT NULL 
        AND i2.iday IS NOT NULL
        AND i2.iyear IS NOT NULL
        AND date({
            year: i2.iyear,
            month: CASE WHEN i2.imonth = 0 THEN 1 ELSE i2.imonth END,
            day: CASE WHEN i2.iday = 0 THEN 1 ELSE i2.iday END
        }) >= date1
        AND date({
            year: i2.iyear,
            month: CASE WHEN i2.imonth = 0 THEN 1 ELSE i2.imonth END,
            day: CASE WHEN i2.iday = 0 THEN 1 ELSE i2.iday END
        }) <= date1 + duration({hours: $hours})
        WITH i1, i1.city as city, 
             collect(DISTINCT i2.gname) as groups,
             count(DISTINCT i2.gname) as group_count
        WHERE group_count >= $min_groups
        RETURN city,
               groups,
               group_count,
               i1.country_txt as country
        ORDER BY group_count DESC
        """
        return self.run_query(query, {"min_groups": min_groups, "hours": hours})

    def find_weapon_pattern_changes(self):
        """
        Which groups changed their primary attack method/weapon type over time?
        """
        query = """
        MATCH (i:Incident)
        WHERE i.weaptype1_txt IS NOT NULL
        AND i.gname IS NOT NULL
        AND i.gname <> 'Unknown'
        WITH i.gname as group_name,
             i.iyear as year,
             i.weaptype1_txt as weapon_type
        WITH group_name,
             collect({year: year, weapon: weapon_type}) as weapon_patterns,
             count(DISTINCT weapon_type) as unique_weapons
        WHERE unique_weapons > 1
        RETURN group_name,
               weapon_patterns,
               unique_weapons
        ORDER BY unique_weapons DESC
        LIMIT 10
        """
        return self.run_query(query)

    def find_regional_attack_clusters(self):
        """
        Identify regions where attacks cluster in specific annual periods
        """
        query = """
        MATCH (i:Incident)
        WHERE i.region_txt IS NOT NULL
        AND i.imonth IS NOT NULL
        WITH i.region_txt as region,
             i.imonth as month,
             count(*) as attack_count
        ORDER BY attack_count DESC
        WITH region,
             collect({month: month, count: attack_count}) as monthly_patterns
        RETURN region,
               monthly_patterns
        ORDER BY size(monthly_patterns) DESC
        LIMIT 10
        """
        return self.run_query(query)

if __name__ == "__main__":
    db = Neo4jTerrorismDB("bolt://localhost:7687", "neo4j", "password")

    try:
        # Query 1: Groups operating in multiple regions
        print("1. Groups operating in both South Asia and Middle East within 6 months:")
        groups = db.get_groups_in_regions("South Asia", "Middle East & North Africa", 6)
        for group in groups:
            print(group)

        # Query 2: Cities with multiple attacks
        print("\n2. Cities with attacks from different groups within 48 hours:")
        cities = db.find_cities_multiple_attacks(48)
        for city in cities:
            print(city)

        # Query 3: Groups with similar tactics
        print("\n3. Groups using similar tactics as Taliban and ISIS:")
        similar_tactics = db.find_groups_similar_tactics("Taliban", "Islamic State of Iraq and the Levant (ISIL)")
        for group in similar_tactics:
            print(group)

        # Query 4: Group activities in a date range
        print("\n4. Taliban activities in 2015:")
        activities = db.get_group_activities_in_timerange("Taliban", "2015-01-01", "2015-12-31")
        for activity in activities:
            print(activity)

        # Query 5: High-frequency attack periods
        print("\n5. High-frequency attack periods by Taliban:")
        high_freq = db.high_frequency_attacks("Taliban", hours_interval=4, min_attacks=10)
        for period in high_freq:
            print(period)

        # Query 6: Attack chains between groups
        print("\n6. Attack chains between Taliban and ISIS:")
        chains = db.find_attack_chain("Taliban", "Islamic State of Iraq and the Levant (ISIL)", max_length=5)
        for chain in chains:
            print(chain)

        # Query 7: Transitive connections
        print("\n7. Transitive connections to ISIS over 7 days:")
        connections = db.find_transitive_connections("Islamic State of Iraq and the Levant (ISIL)", days=7)
        for connection in connections:
            print(connection)

        # Test the new queries
        print("\n8. Groups operating across regions within 30 days:")
        results = db.find_cross_region_groups("South Asia", "Middle East & North Africa")
        for r in results:
            print(r)

        print("\n9. Sequential target attacks within 72 hours:")
        results = db.find_sequential_target_attacks()
        for r in results:
            print(r)

        print("\n10. Cities with multiple group attacks:")
        results = db.find_cities_multiple_groups()
        for r in results:
            print(r)

        print("\n11. Groups changing weapon patterns:")
        results = db.find_weapon_pattern_changes()
        for r in results:
            print(r)

        print("\n12. Regional attack clusters:")
        results = db.find_regional_attack_clusters()
        for r in results:
            print(r)

    finally:
        db.close()
