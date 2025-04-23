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
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", password="password"):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def run_query(self, query, parameters=None):
        with self.driver.session() as session:
            result = session.run(query, parameters or {})
            return [record.data() for record in result]

    @staticmethod
    def _incident_date(alias="i"):
        """Return a Cypher snippet that converts y/m/d on node `alias` to a date()."""
        return f"""
            date({{
                year: {alias}.iyear,
                month: CASE WHEN {alias}.imonth IS NULL OR {alias}.imonth <= 0
                            THEN 1 ELSE {alias}.imonth END,
                day:   CASE WHEN {alias}.iday   IS NULL OR {alias}.iday   <= 0
                            THEN 1 ELSE {alias}.iday   END
            }})
        """

    def find_time_ordered_path(
        self,
        start_label: str,
        end_label: str,
        max_path_length: int = 3,
        time_window_minutes: int = 120,
        overall_start_date: str | None = None,
        overall_end_date: str | None = None,
    ):
        """
        Return paths from `start_label` to `end_label` such that:

        * path length ≤ L (`max_path_length`)
        * timestamps of successive incidents strictly increase
        * first incident date ≥ `overall_start_date` (if provided)
        * last incident date ≤ `overall_end_date` (if provided)
        * every hop occurs ≤ T minutes after the previous hop (`time_window_minutes`)
        * traversal is along :SIMILAR_ATTACK relationships that you have already
          created in your graph.

        """
        query = f"""
        // -------------- collect possible start incidents ------------------
        MATCH (start:Incident)
        WHERE start.targtype1_txt = $start_label
          AND start.iyear  IS NOT NULL
          AND start.imonth IS NOT NULL AND start.imonth > 0
          AND start.iday   IS NOT NULL AND start.iday   > 0
        WITH start LIMIT 200   // cap fan-out for performance

        // -------------- traverse up to L hops -----------------------------
        MATCH p = (start)-[:SIMILAR_ATTACK*1..{max_path_length}]->(end:Incident)
        WHERE end.targtype1_txt = $end_label
          AND end <> start
          AND end.iyear  IS NOT NULL AND end.imonth IS NOT NULL AND end.iday IS NOT NULL

        WITH p, nodes(p) AS incs

        // -------------- make sure every node has a clean date -------------
        WHERE all(i IN incs WHERE i.iyear IS NOT NULL
                               AND i.imonth IS NOT NULL AND i.imonth > 0
                               AND i.iday   IS NOT NULL AND i.iday   > 0)

        // convert to Cypher date list
        WITH p, [i IN incs | {self._incident_date("i")}] AS ts, incs

        // -------------- ordering & window constraints ---------------------
        WHERE size(ts) < 2
           OR reduce(ok = true, idx IN range(0, size(ts)-2) |
                        ok AND ts[idx] < ts[idx+1]
                           AND duration.between(ts[idx],ts[idx+1]).minutes
                               <= $time_window_minutes)
                       AND ($overall_start_date IS NULL OR ts[0] >= date($overall_start_date))
                       AND ($overall_end_date   IS NULL OR ts[size(ts)-1] <= date($overall_end_date))

        RETURN
            length(p) AS path_len,
            [n IN incs | {{
                id: n.eventid,
                group: n.gname,
                date: {self._incident_date("n")},
                city: n.city,
                country: n.country_txt
            }}] AS incidents
        ORDER BY path_len, incidents[0].date
        LIMIT 25
        """
        return self.run_query(
            query,
            {
                "start_label": start_label,
                "end_label":   end_label,
                "time_window_minutes": time_window_minutes,
                "overall_start_date": overall_start_date,
                "overall_end_date":   overall_end_date,
            },
        )

    def get_groups_in_regions(self, region1, region2, months=6):
        """Find groups that operated in both specified regions within a time period."""
        query = """
        MATCH (i1:Incident)
        WHERE i1.region_txt = $region1 AND i1.gname IS NOT NULL AND i1.gname <> 'Unknown'
        WITH i1, date({
            year: i1.iyear, 
            month: CASE WHEN i1.imonth IS NULL OR i1.imonth <= 0 THEN 1 ELSE i1.imonth END, 
            day: CASE WHEN i1.iday IS NULL OR i1.iday <= 0 THEN 1 ELSE i1.iday END
        }) AS date1
        MATCH (i2:Incident)
        WHERE i2.gname = i1.gname 
        AND i2.region_txt = $region2
        AND date({
            year: i2.iyear, 
            month: CASE WHEN i2.imonth IS NULL OR i2.imonth <= 0 THEN 1 ELSE i2.imonth END, 
            day: CASE WHEN i2.iday IS NULL OR i2.iday <= 0 THEN 1 ELSE i2.iday END
        }) >= date1
        AND date({
            year: i2.iyear, 
            month: CASE WHEN i2.imonth IS NULL OR i2.imonth <= 0 THEN 1 ELSE i2.imonth END, 
            day: CASE WHEN i2.iday IS NULL OR i2.iday <= 0 THEN 1 ELSE i2.iday END
        }) <= date1 + duration({months: $months})
        RETURN DISTINCT i1.gname AS GroupName,
               count(i1) + count(i2) AS TotalAttacks
        ORDER BY TotalAttacks DESC
        """
        return self.run_query(query, {
            "region1": region1,
            "region2": region2,
            "months": months
        })

    def find_cities_multiple_attacks(self, hours=48):
        """Find cities that experienced attacks from different groups within specified hours."""
        query = """
        MATCH (i1:Incident)
        WHERE i1.city IS NOT NULL
        AND i1.iyear IS NOT NULL AND i1.imonth IS NOT NULL AND i1.iday IS NOT NULL
        WITH i1, datetime({
            year: i1.iyear,
            month: CASE WHEN i1.imonth <= 0 THEN 1 ELSE i1.imonth END,
            day: CASE WHEN i1.iday <= 0 THEN 1 ELSE i1.iday END
        }) AS dt1
        MATCH (i2:Incident)
        WHERE i2.city = i1.city 
        AND i1 <> i2  // Prevent self-matches
        AND i2.gname <> i1.gname
        AND i2.iyear IS NOT NULL AND i2.imonth IS NOT NULL AND i2.iday IS NOT NULL
        WITH i1, dt1, i2, datetime({
            year: i2.iyear,
            month: CASE WHEN i2.imonth <= 0 THEN 1 ELSE i2.imonth END,
            day: CASE WHEN i2.iday <= 0 THEN 1 ELSE i2.iday END
        }) AS dt2
        WHERE duration.between(dt1, dt2).hours <= $hours
        RETURN i1.city AS City,
               apoc.coll.toSet(collect(DISTINCT i1.gname) + collect(DISTINCT i2.gname)) AS Groups,
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
        AND ANY(tactic IN [i3.attacktype1] WHERE tactic IN g1_tactics AND tactic IN g2_tactics)
        RETURN DISTINCT i3.gname AS GroupName,
               collect(DISTINCT i3.attacktype1_txt) AS SharedTactics,
               count(DISTINCT i3) AS AttackCount
        ORDER BY AttackCount DESC
        """
        return self.run_query(query, {"group1": group1, "group2": group2})

    def get_group_activities_in_timerange(self, group_name, start_date, end_date):
        """Get activities by a group in a specific date range."""
        query = """
        MATCH (i:Incident)
        WHERE i.gname = $group_name
        AND date({
            year: i.iyear, 
            month: CASE WHEN i.imonth IS NULL OR i.imonth <= 0 THEN 1 ELSE i.imonth END, 
            day: CASE WHEN i.iday IS NULL OR i.iday <= 0 THEN 1 ELSE i.iday END
        }) >= date($start_date)
        AND date({
            year: i.iyear, 
            month: CASE WHEN i.imonth IS NULL OR i.imonth <= 0 THEN 1 ELSE i.imonth END, 
            day: CASE WHEN i.iday IS NULL OR i.iday <= 0 THEN 1 ELSE i.iday END
        }) <= date($end_date)
        RETURN i.eventid AS EventID, i.city AS City,
               date({
                   year: i.iyear, 
                   month: CASE WHEN i.imonth IS NULL OR i.imonth <= 0 THEN 1 ELSE i.imonth END, 
                   day: CASE WHEN i.iday IS NULL OR i.iday <= 0 THEN 1 ELSE i.iday END
               }) AS Date,
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
        WITH date({
            year: i.iyear, 
            month: CASE WHEN i.imonth IS NULL OR i.imonth <= 0 THEN 1 ELSE i.imonth END, 
            day: CASE WHEN i.iday IS NULL OR i.iday <= 0 THEN 1 ELSE i.iday END
        }) AS attack_date,
             i.city AS location,
             i.eventid as event_id
        WITH attack_date, 
             collect({loc: location, id: event_id}) as attacks
        WITH attack_date,
             [x IN attacks WHERE duration.between(attack_date, 
                 attack_date + duration({hours: $hours})).hours <= $hours] as window_attacks,
             attacks[0].loc as location
        WHERE size(window_attacks) >= $min_attacks
        RETURN attack_date AS Date, 
               size(window_attacks) AS AttackCount,
               [x IN window_attacks | x.loc] AS Locations
        ORDER BY attack_date
        """
        return self.run_query(query, {
            "group_name": group_name,
            "hours": hours_interval,
            "min_attacks": min_attacks
        })

    def find_attack_chain(self, start_group, end_group, max_length=None):
        """Find attack chains linking two groups through shared locations or tactics."""
        max_length = 5 if max_length is None else max_length
        query = f"""
        MATCH path = (start:Incident)-[:SIMILAR_ATTACK*1..{max_length}]->(end:Incident)
        WHERE start.gname = $start_group
        AND end.gname = $end_group
        AND start.iyear <= end.iyear
        AND length(path) <= {max_length}
        RETURN DISTINCT {{
            path_length: length(path),
            attacks: [x IN nodes(path) | {{
                group: x.gname,
                date: date({{
                    year: x.iyear, 
                    month: CASE WHEN x.imonth IS NULL OR x.imonth <= 0 THEN 1 ELSE x.imonth END, 
                    day: CASE WHEN x.iday IS NULL OR x.iday <= 0 THEN 1 ELSE x.iday END
                }}),
                location: x.city,
                attack_type: x.attacktype1_txt
            }}]
        }} AS chain
        ORDER BY chain.path_length
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
        WITH i1, date({
            year: i1.iyear, 
            month: CASE WHEN i1.imonth IS NULL OR i1.imonth <= 0 THEN 1 ELSE i1.imonth END, 
            day: CASE WHEN i1.iday IS NULL OR i1.iday <= 0 THEN 1 ELSE i1.iday END
        }) AS date1
        MATCH (i2:Incident)
        WHERE i2.region_txt = $region2 
        AND i2.gname = i1.gname
        AND i2.gname IS NOT NULL 
        AND i2.gname <> 'Unknown'
        AND date({
            year: i2.iyear, 
            month: CASE WHEN i2.imonth IS NULL OR i2.imonth <= 0 THEN 1 ELSE i2.imonth END, 
            day: CASE WHEN i2.iday IS NULL OR i2.iday <= 0 THEN 1 ELSE i2.iday END
        }) >= date1
        AND date({
            year: i2.iyear, 
            month: CASE WHEN i2.imonth IS NULL OR i2.imonth <= 0 THEN 1 ELSE i2.imonth END, 
            day: CASE WHEN i2.iday IS NULL OR i2.iday <= 0 THEN 1 ELSE i2.iday END
        }) <= date1 + duration({days: $days})
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
            month: CASE WHEN i1.imonth <= 0 THEN 1 ELSE i1.imonth END,
            day: CASE WHEN i1.iday <= 0 THEN 1 ELSE i1.iday END
        }) AS date1
        MATCH (i2:Incident)
        WHERE i2.targtype1_txt = i1.targtype1_txt
        AND i2.gname <> i1.gname
        AND i2.imonth IS NOT NULL 
        AND i2.iday IS NOT NULL
        AND i2.iyear IS NOT NULL
        AND date({
            year: i2.iyear,
            month: CASE WHEN i2.imonth <= 0 THEN 1 ELSE i2.imonth END,
            day: CASE WHEN i2.iday <= 0 THEN 1 ELSE i2.iday END
        }) > date1
        AND date({
            year: i2.iyear,
            month: CASE WHEN i2.imonth <= 0 THEN 1 ELSE i2.imonth END,
            day: CASE WHEN i2.iday <= 0 THEN 1 ELSE i2.iday END
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
                       month: CASE WHEN i2.imonth <= 0 THEN 1 ELSE i2.imonth END,
                       day: CASE WHEN i2.iday <= 0 THEN 1 ELSE i2.iday END
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
            month: CASE WHEN i1.imonth <= 0 THEN 1 ELSE i1.imonth END,
            day: CASE WHEN i1.iday <= 0 THEN 1 ELSE i1.iday END
        }) AS date1
        MATCH (i2:Incident)
        WHERE i2.city = i1.city
        AND i2.imonth IS NOT NULL 
        AND i2.iday IS NOT NULL
        AND i2.iyear IS NOT NULL
        AND date({
            year: i2.iyear,
            month: CASE WHEN i2.imonth <= 0 THEN 1 ELSE i2.imonth END,
            day: CASE WHEN i2.iday <= 0 THEN 1 ELSE i2.iday END
        }) >= date1
        AND date({
            year: i2.iyear,
            month: CASE WHEN i2.imonth <= 0 THEN 1 ELSE i2.imonth END,
            day: CASE WHEN i2.iday <= 0 THEN 1 ELSE i2.iday END
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

    def find_potential_coordination(self, days_window=30, similarity_threshold=0.5):
        """Find groups that may be coordinating based on similar attack patterns within a time window."""
        query = """
        MATCH (i1:Incident)
        WHERE i1.gname IS NOT NULL AND i1.gname <> 'Unknown'
        WITH i1, date({
            year: i1.iyear,
            month: CASE WHEN i1.imonth IS NULL OR i1.imonth <= 0 THEN 1 ELSE i1.imonth END,
            day: CASE WHEN i1.iday IS NULL OR i1.iday <= 0 THEN 1 ELSE i1.iday END
        }) AS date1
        
        MATCH (i2:Incident)
        WHERE i2.gname <> i1.gname 
        AND i2.gname IS NOT NULL 
        AND i2.gname <> 'Unknown'
        AND date({
            year: i2.iyear,
            month: CASE WHEN i2.imonth IS NULL OR i2.imonth <= 0 THEN 1 ELSE i2.imonth END,
            day: CASE WHEN i2.iday IS NULL OR i2.iday <= 0 THEN 1 ELSE i2.iday END
        }) >= date1
        AND date({
            year: i2.iyear,
            month: CASE WHEN i2.imonth IS NULL OR i2.imonth <= 0 THEN 1 ELSE i2.imonth END,
            day: CASE WHEN i2.iday IS NULL OR i2.iday <= 0 THEN 1 ELSE i2.iday END
        }) <= date1 + duration({days: $days})
        
        WITH i1, i2,
            // Calculate weighted similarity components with null handling
            (CASE 
                WHEN i1.weaptype1_txt = i2.weaptype1_txt 
                AND i1.weaptype1_txt IS NOT NULL THEN 0.35
                ELSE 0 
            END +
            CASE 
                WHEN i1.targtype1_txt = i2.targtype1_txt 
                AND i1.targtype1_txt IS NOT NULL THEN 0.35
                ELSE 0 
            END +
            CASE 
                WHEN i1.region_txt = i2.region_txt 
                AND i1.region_txt IS NOT NULL THEN 0.15
                ELSE 0 
            END +
            CASE 
                WHEN i1.country_txt = i2.country_txt 
                AND i1.country_txt IS NOT NULL THEN 0.15
                ELSE 0 
            END) AS similarity_score,
            
            CASE 
                WHEN i1.weaptype1_txt IS NOT NULL AND i2.weaptype1_txt IS NOT NULL 
                THEN i1.weaptype1_txt = i2.weaptype1_txt 
                ELSE false 
            END AS weapon_match,
            
            CASE 
                WHEN i1.targtype1_txt IS NOT NULL AND i2.targtype1_txt IS NOT NULL 
                THEN i1.targtype1_txt = i2.targtype1_txt 
                ELSE false 
            END AS target_match,
            
            CASE 
                WHEN i1.region_txt IS NOT NULL AND i2.region_txt IS NOT NULL 
                THEN i1.region_txt = i2.region_txt 
                ELSE false 
            END AS region_match,
            
            CASE 
                WHEN i1.country_txt IS NOT NULL AND i2.country_txt IS NOT NULL 
                THEN i1.country_txt = i2.country_txt 
                ELSE false 
            END AS country_match,
            
            duration.between(
                date({
                    year: i1.iyear,
                    month: CASE WHEN i1.imonth IS NULL OR i1.imonth <= 0 THEN 1 ELSE i1.imonth END,
                    day: CASE WHEN i1.iday IS NULL OR i1.iday <= 0 THEN 1 ELSE i1.iday END
                }),
                date({
                    year: i2.iyear,
                    month: CASE WHEN i2.imonth IS NULL OR i2.imonth <= 0 THEN 1 ELSE i2.imonth END,
                    day: CASE WHEN i2.iday IS NULL OR i2.iday <= 0 THEN 1 ELSE i2.iday END
                })
            ).days AS days_between
        
        WHERE similarity_score >= $threshold
        
        WITH i1.gname AS group1, 
             i2.gname AS group2,
             collect({
                 similarity_score: similarity_score,
                 days_between: days_between,
                 weapon_match: weapon_match,
                 target_match: target_match,
                 region_match: region_match,
                 country_match: country_match,
                 attack1: {
                     date: date({
                         year: i1.iyear,
                         month: CASE WHEN i1.imonth IS NULL OR i1.imonth <= 0 THEN 1 ELSE i1.imonth END,
                         day: CASE WHEN i1.iday IS NULL OR i1.iday <= 0 THEN 1 ELSE i1.iday END
                     }),
                     location: CASE WHEN i1.city IS NULL THEN 'Unknown' ELSE i1.city END + ', ' + 
                               CASE WHEN i1.country_txt IS NULL THEN 'Unknown' ELSE i1.country_txt END,
                     weapon: CASE WHEN i1.weaptype1_txt IS NULL THEN 'Unknown' ELSE i1.weaptype1_txt END,
                     target: CASE WHEN i1.targtype1_txt IS NULL THEN 'Unknown' ELSE i1.targtype1_txt END
                 },
                 attack2: {
                     date: date({
                         year: i2.iyear,
                         month: CASE WHEN i2.imonth IS NULL OR i2.imonth <= 0 THEN 1 ELSE i2.imonth END,
                         day: CASE WHEN i2.iday IS NULL OR i2.iday <= 0 THEN 1 ELSE i2.iday END
                     }),
                     location: CASE WHEN i2.city IS NULL THEN 'Unknown' ELSE i2.city END + ', ' + 
                               CASE WHEN i2.country_txt IS NULL THEN 'Unknown' ELSE i2.country_txt END,
                     weapon: CASE WHEN i2.weaptype1_txt IS NULL THEN 'Unknown' ELSE i2.weaptype1_txt END,
                     target: CASE WHEN i2.targtype1_txt IS NULL THEN 'Unknown' ELSE i2.targtype1_txt END
                 }
             }) AS incident_pairs

        UNWIND incident_pairs AS pair
        WITH group1, group2, incident_pairs,
             avg(CASE WHEN pair.similarity_score IS NULL THEN 0 ELSE pair.similarity_score END) AS avg_similarity,
             avg(CASE WHEN pair.days_between IS NULL THEN 0 ELSE pair.days_between END) AS avg_days_between,
             collect(DISTINCT CASE WHEN pair.weapon_match THEN 'weapon' ELSE '' END) AS weapon_matches_raw,
             collect(DISTINCT CASE WHEN pair.target_match THEN 'target' ELSE '' END) AS target_matches_raw,
             collect(DISTINCT CASE WHEN pair.region_match THEN 'region' ELSE '' END) AS region_matches_raw,
             collect(DISTINCT CASE WHEN pair.country_match THEN 'country' ELSE '' END) AS country_matches_raw
        
        WITH group1, group2, incident_pairs,
             round(10 * avg_similarity) / 10.0 AS similarity_score,
             avg_days_between,
             [x IN weapon_matches_raw WHERE x <> ''] AS weapon_matches,
             [x IN target_matches_raw WHERE x <> ''] AS target_matches,
             [x IN region_matches_raw WHERE x <> ''] AS region_matches,
             [x IN country_matches_raw WHERE x <> ''] AS country_matches
        
        WITH group1, group2, incident_pairs, similarity_score, avg_days_between,
             weapon_matches + target_matches + region_matches + country_matches AS matches
        
        RETURN 
            group1,
            group2,
            similarity_score,
            avg_days_between,
            CASE WHEN size(matches) = 0 
                 THEN '' 
                 ELSE reduce(s = '', m IN matches | s + (CASE WHEN s = '' THEN '' ELSE ' ' END) + m) 
            END AS matching_criteria,
            incident_pairs AS similar_attacks
        
        ORDER BY similarity_score DESC, avg_days_between
        LIMIT 100
        """
        return self.run_query(query, {
            "days": days_window,
            "threshold": similarity_threshold
        })

    def create_similarity_relationships(self, similarity_threshold=0.7, days_window=30):
        """Create SIMILAR_ATTACK relationships between incidents that have similar characteristics."""
        setup_query = """
        CREATE INDEX incident_id IF NOT EXISTS FOR (i:Incident) ON (i.eventid)
        """
        self.run_query(setup_query)
        
        query = """
        MATCH (i1:Incident)
        WHERE i1.gname IS NOT NULL AND i1.gname <> 'Unknown'
        AND i1.iyear IS NOT NULL AND i1.imonth IS NOT NULL AND i1.iday IS NOT NULL
        WITH i1, datetime({
            year: i1.iyear,
            month: CASE WHEN i1.imonth <= 0 THEN 1 ELSE i1.imonth END,
            day: CASE WHEN i1.iday <= 0 THEN 1 ELSE i1.iday END
        }) AS dt1
        
        MATCH (i2:Incident)
        WHERE i2.gname <> i1.gname 
        AND i2.gname IS NOT NULL 
        AND i2.gname <> 'Unknown'
        AND i1.eventid < i2.eventid  // Prevent duplicate relationships
        AND i2.iyear IS NOT NULL AND i2.imonth IS NOT NULL AND i2.iday IS NOT NULL
        WITH i1, dt1, i2, datetime({
            year: i2.iyear,
            month: CASE WHEN i2.imonth <= 0 THEN 1 ELSE i2.imonth END,
            day: CASE WHEN i2.iday <= 0 THEN 1 ELSE i2.iday END
        }) AS dt2
        
        WITH i1, i2,
             toFloat(
                 CASE WHEN i1.weaptype1_txt = i2.weaptype1_txt THEN 30 ELSE 0 END +
                 CASE WHEN i1.targtype1_txt = i2.targtype1_txt THEN 30 ELSE 0 END +
                 CASE WHEN i1.region_txt = i2.region_txt THEN 20 ELSE 0 END +
                 CASE WHEN i1.country_txt = i2.country_txt THEN 20 ELSE 0 END
             ) / 100.0 AS similarity_score
             
        WHERE similarity_score >= $threshold
        AND duration.between(dt1, dt2).days <= $days
        
        MERGE (i1)-[r:SIMILAR_ATTACK]->(i2)
        SET r.similarity_score = similarity_score
        """
        return self.run_query(query, {"days": days_window, "threshold": similarity_threshold})

    def find_indirect_connections(self, group1, group2, max_intermediaries=2, days_window=60):
        """Find potential indirect connections between two groups through intermediaries."""
        self.create_similarity_relationships()
        
        query = """
        MATCH path = (i1:Incident)-[:SIMILAR_ATTACK*1..10]->(i2:Incident)
        WHERE i1.gname = $group1 
        AND i2.gname = $group2
        AND length(path) - 1 <= $max_intermediaries  // Correct path length calculation
        AND all(r IN relationships(path) WHERE r.similarity_score >= 0.7)
        AND all(x IN nodes(path) WHERE 
            duration.between(
                datetime({
                    year: i1.iyear,
                    month: CASE WHEN i1.imonth <= 0 THEN 1 ELSE i1.imonth END,
                    day: CASE WHEN i1.iday <= 0 THEN 1 ELSE i1.iday END
                }),
                datetime({
                    year: x.iyear,
                    month: CASE WHEN x.imonth <= 0 THEN 1 ELSE x.imonth END,
                    day: CASE WHEN x.iday <= 0 THEN 1 ELSE x.iday END
                })
            ).days <= $days
        )
        RETURN path,
               [x IN nodes(path) | x.gname] as groups,
               [x IN nodes(path) | {
                   date: datetime({
                       year: x.iyear,
                       month: CASE WHEN x.imonth <= 0 THEN 1 ELSE x.imonth END,
                       day: CASE WHEN x.iday <= 0 THEN 1 ELSE x.iday END
                   }),
                   location: x.city + ', ' + x.country_txt,
                   weapon: x.weaptype1_txt,
                   target: x.targtype1_txt
               }] as attacks,
               length(path) as path_length
        ORDER BY path_length
        LIMIT 10
        """
        return self.run_query(query, {
            "group1": group1,
            "group2": group2,
            "max_intermediaries": max_intermediaries,
            "days": days_window
        })

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

        # Find potential direct coordination
        print("\n13. Groups with similar attack patterns within 30 days:")
        results = db.find_potential_coordination(days_window=30)
        for r in results:
            print(f"Groups {r['group1']} and {r['group2']} - Similarity: {r['similarity_score']} (Matched:{r['matching_criteria']})")
            for attack_pair in r['similar_attacks']:
                print(f"  {attack_pair['attack1']['date']} -> {attack_pair['attack2']['date']}")

        # Find indirect connections
        print("\n14. Indirect connections between Taliban and ISIS:")
        results = db.find_indirect_connections(
            "Taliban", 
            "Islamic State of Iraq and the Levant (ISIL)", 
            max_intermediaries=2
        )
        for r in results:
            print(f"Connection path: {' -> '.join(r['groups'])}")
            for attack in r['attacks']:
                print(f"  {attack['date']}: {attack['location']}")

        # Demo the new time-ordered path query
        print("\n15. Demo: time-ordered path (L=3, T=120 min, Range: 1970-1971)")
        paths = db.find_time_ordered_path(
            "Police",        # targtype1_txt of first "person"
            "Military",      # targtype1_txt of second "person"
            max_path_length=3,
            time_window_minutes=120,
            overall_start_date="1970-01-01",
            overall_end_date="1971-12-31",
        )
        for p in paths:
            print(p)

    finally:
        db.close()
