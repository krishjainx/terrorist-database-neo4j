#!/bin/bash

set -e  
set -x  

# Step 0: Clean up existing Neo4j container
podman container rm -f neo4j || true

# Step 1: Pull Neo4j with APOC Plugin
podman pull neo4j:latest

# Step 2: Run Neo4j container with APOC enabled
podman run -d \
  --name neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/password \
  -e NEO4JLABS_PLUGINS='["apoc"]' \
  -e dbms.security.procedures.unrestricted=apoc.* \
  neo4j:latest

# Step 3: Wait for Neo4j to initialize
echo "Waiting for Neo4j to initialize..."
sleep 30  

# Step 4: Copy the original dataset into the container
podman cp globalterrorismdb_0718dist.csv neo4j:/var/lib/neo4j/import/

# Step 5: Import data into Neo4j with quote handling
cat <<EOF | podman exec -i neo4j cypher-shell -u neo4j -p password
CALL apoc.periodic.iterate(
  "LOAD CSV WITH HEADERS FROM 'file:///globalterrorismdb_0718dist.csv' AS row RETURN row",
  '
  MERGE (i:Incident {eventid: row.eventid})
  SET i.iyear = CASE WHEN row.iyear IS NOT NULL AND row.iyear <> "" THEN toInteger(row.iyear) ELSE null END,
      i.imonth = CASE WHEN row.imonth IS NOT NULL AND row.imonth <> "" THEN toInteger(row.imonth) ELSE null END,
      i.iday = CASE WHEN row.iday IS NOT NULL AND row.iday <> "" THEN toInteger(row.iday) ELSE null END,
      i.approxdate = row.approxdate,
      i.extended = CASE WHEN row.extended IS NOT NULL AND row.extended <> "" THEN toBoolean(row.extended) ELSE null END,
      i.resolution = row.resolution,
      i.country = CASE WHEN row.country IS NOT NULL AND row.country <> "" THEN toInteger(row.country) ELSE null END,
      i.country_txt = row.country_txt,
      i.region = CASE WHEN row.region IS NOT NULL AND row.region <> "" THEN toInteger(row.region) ELSE null END,
      i.region_txt = row.region_txt,
      i.provstate = row.provstate,
      i.city = row.city,
      i.latitude = CASE WHEN row.latitude IS NOT NULL AND row.latitude <> "" THEN toFloat(row.latitude) ELSE null END,
      i.longitude = CASE WHEN row.longitude IS NOT NULL AND row.longitude <> "" THEN toFloat(row.longitude) ELSE null END,
      i.specificity = CASE WHEN row.specificity IS NOT NULL AND row.specificity <> "" THEN toInteger(row.specificity) ELSE null END,
      i.vicinity = CASE WHEN row.vicinity IS NOT NULL AND row.vicinity <> "" THEN toBoolean(row.vicinity) ELSE null END,
      i.location = row.location,
      i.summary = row.summary,
      i.crit1 = CASE WHEN row.crit1 IS NOT NULL AND row.crit1 <> "" THEN toBoolean(row.crit1) ELSE null END,
      i.crit2 = CASE WHEN row.crit2 IS NOT NULL AND row.crit2 <> "" THEN toBoolean(row.crit2) ELSE null END,
      i.crit3 = CASE WHEN row.crit3 IS NOT NULL AND row.crit3 <> "" THEN toBoolean(row.crit3) ELSE null END,
      i.doubtterr = CASE WHEN row.doubtterr IS NOT NULL AND row.doubtterr <> "" THEN toBoolean(row.doubtterr) ELSE null END,
      i.alternative = row.alternative,
      i.alternative_txt = row.alternative_txt,
      i.multiple = CASE WHEN row.multiple IS NOT NULL AND row.multiple <> "" THEN toBoolean(row.multiple) ELSE null END,
      i.success = CASE WHEN row.success IS NOT NULL AND row.success <> "" THEN toBoolean(row.success) ELSE null END,
      i.suicide = CASE WHEN row.suicide IS NOT NULL AND row.suicide <> "" THEN toBoolean(row.suicide) ELSE null END,
      i.attacktype1 = CASE WHEN row.attacktype1 IS NOT NULL AND row.attacktype1 <> "" THEN toInteger(row.attacktype1) ELSE null END,
      i.attacktype1_txt = row.attacktype1_txt,
      i.attacktype2 = CASE WHEN row.attacktype2 IS NOT NULL AND row.attacktype2 <> "" THEN toInteger(row.attacktype2) ELSE null END,
      i.attacktype2_txt = row.attacktype2_txt,
      i.attacktype3 = CASE WHEN row.attacktype3 IS NOT NULL AND row.attacktype3 <> "" THEN toInteger(row.attacktype3) ELSE null END,
      i.attacktype3_txt = row.attacktype3_txt,
      i.targtype1 = CASE WHEN row.targtype1 IS NOT NULL AND row.targtype1 <> "" THEN toInteger(row.targtype1) ELSE null END,
      i.targtype1_txt = row.targtype1_txt,
      i.target1 = row.target1,
      i.natlty1 = CASE WHEN row.natlty1 IS NOT NULL AND row.natlty1 <> "" THEN toInteger(row.natlty1) ELSE null END,
      i.natlty1_txt = row.natlty1_txt,
      i.nkill = CASE WHEN row.nkill IS NOT NULL AND row.nkill <> "" THEN toInteger(row.nkill) ELSE null END,
      i.nwound = CASE WHEN row.nwound IS NOT NULL AND row.nwound <> "" THEN toInteger(row.nwound) ELSE null END,
      i.gname = row.gname,
      i.motive = row.motive
  ',
  {batchSize: 500, parallel: true}
)
EOF

# Seems like I am currently facing issues with the import. I'll try to fix it later. Need to properly fix the CSV file. Tried using OpenRefine but it didn't work.

# Error at the moment: Failed to invoke procedure `apoc.periodic.iterate`: Caused by: org.neo4j.csv.reader.DataAfterQuoteException: At /var/lib/neo4j/import/globalterrorismdb-0718dist-csv.csv @ position 56166296 -  there's a field starting with a quote and whereas it ends that quote there seems to be characters in that field after that ending quote. That isn't supported. This is what I read: 'satp.org: South Asia Terrorism Portal, "Suspected Maoists Blast Tractors in Andhra Pradesh," November 04, 2008, http://www.satp.org/satporgtp/detailed_news.asp?date1=11/4/2008#3",,ISVG,0,0,0,0,
# 200811020018,2008,11,2,,1,,153,Pakistan,6,South Asia,North-West Frontier Province,Drosh,35.560714,71.797266,1,1,"A,"A'




echo "Data import complete. Query data using the Python script."
