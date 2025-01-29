#!/bin/bash

set -e  
set -x  

# Detect container runtime
if command -v podman &> /dev/null; then
    CONTAINER_CMD="podman"
elif command -v docker &> /dev/null; then
    CONTAINER_CMD="docker" 
else
    echo "Error: Neither podman nor docker found. Please install one of them."
    exit 1
fi

# Step 0: Clean up existing Neo4j container
$CONTAINER_CMD container rm -f neo4j || true

# Step 1: Pull Neo4j with APOC Plugin
$CONTAINER_CMD pull neo4j:latest

# Step 2: Run Neo4j container with APOC enabled
$CONTAINER_CMD run -d \
  --name neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/password \
  -e NEO4JLABS_PLUGINS='["apoc"]' \
  -e dbms.security.procedures.unrestricted=apoc.* \
  neo4j:latest

# Step 3: Wait for Neo4j to initialize
echo "Waiting for Neo4j to initialize..."
sleep 30  

# Step 4: Copy the dataset into the container
$CONTAINER_CMD cp globalterrorismdb_0718dist.csv neo4j:/var/lib/neo4j/import/

# Step 5: Import first 100 rows with correct data types
cat <<EOF | $CONTAINER_CMD exec -i neo4j cypher-shell -u neo4j -p password
CALL apoc.periodic.iterate(
  "LOAD CSV WITH HEADERS FROM 'file:///globalterrorismdb_0718dist.csv' AS row RETURN row LIMIT 1000",
  '
  MERGE (i:Incident {eventid: toInteger(row.eventid)})
  SET 
      // Integer fields
      i.iyear = toInteger(row.iyear),
      i.imonth = toInteger(row.imonth),
      i.iday = toInteger(row.iday),
      i.extended = toInteger(row.extended),
      i.country = toInteger(row.country),
      i.region = toInteger(row.region),
      i.vicinity = toInteger(row.vicinity),
      i.crit1 = toInteger(row.crit1),
      i.crit2 = toInteger(row.crit2),
      i.crit3 = toInteger(row.crit3),
      i.success = toInteger(row.success),
      i.suicide = toInteger(row.suicide),
      i.attacktype1 = toInteger(row.attacktype1),
      i.targtype1 = toInteger(row.targtype1),
      i.individual = toInteger(row.individual),
      i.weaptype1 = toInteger(row.weaptype1),
      i.property = toInteger(row.property),
      i.INT_LOG = toInteger(row.INT_LOG),
      i.INT_IDEO = toInteger(row.INT_IDEO),
      i.INT_MISC = toInteger(row.INT_MISC),
      i.INT_ANY = toInteger(row.INT_ANY),

      // Float fields
      i.latitude = CASE WHEN row.latitude IS NOT NULL AND row.latitude <> "" THEN toFloat(row.latitude) ELSE null END,
      i.longitude = CASE WHEN row.longitude IS NOT NULL AND row.longitude <> "" THEN toFloat(row.longitude) ELSE null END,
      i.specificity = CASE WHEN row.specificity IS NOT NULL AND row.specificity <> "" THEN toFloat(row.specificity) ELSE null END,
      i.doubtterr = CASE WHEN row.doubtterr IS NOT NULL AND row.doubtterr <> "" THEN toFloat(row.doubtterr) ELSE null END,
      i.alternative = CASE WHEN row.alternative IS NOT NULL AND row.alternative <> "" THEN toFloat(row.alternative) ELSE null END,
      i.multiple = CASE WHEN row.multiple IS NOT NULL AND row.multiple <> "" THEN toFloat(row.multiple) ELSE null END,
      i.attacktype2 = CASE WHEN row.attacktype2 IS NOT NULL AND row.attacktype2 <> "" THEN toFloat(row.attacktype2) ELSE null END,
      i.attacktype3 = CASE WHEN row.attacktype3 IS NOT NULL AND row.attacktype3 <> "" THEN toFloat(row.attacktype3) ELSE null END,
      i.targsubtype1 = CASE WHEN row.targsubtype1 IS NOT NULL AND row.targsubtype1 <> "" THEN toFloat(row.targsubtype1) ELSE null END,
      i.natlty1 = CASE WHEN row.natlty1 IS NOT NULL AND row.natlty1 <> "" THEN toFloat(row.natlty1) ELSE null END,
      i.targtype2 = CASE WHEN row.targtype2 IS NOT NULL AND row.targtype2 <> "" THEN toFloat(row.targtype2) ELSE null END,
      i.targsubtype2 = CASE WHEN row.targsubtype2 IS NOT NULL AND row.targsubtype2 <> "" THEN toFloat(row.targsubtype2) ELSE null END,
      i.natlty2 = CASE WHEN row.natlty2 IS NOT NULL AND row.natlty2 <> "" THEN toFloat(row.natlty2) ELSE null END,
      i.targtype3 = CASE WHEN row.targtype3 IS NOT NULL AND row.targtype3 <> "" THEN toFloat(row.targtype3) ELSE null END,
      i.targsubtype3 = CASE WHEN row.targsubtype3 IS NOT NULL AND row.targsubtype3 <> "" THEN toFloat(row.targsubtype3) ELSE null END,
      i.natlty3 = CASE WHEN row.natlty3 IS NOT NULL AND row.natlty3 <> "" THEN toFloat(row.natlty3) ELSE null END,
      i.guncertain1 = CASE WHEN row.guncertain1 IS NOT NULL AND row.guncertain1 <> "" THEN toFloat(row.guncertain1) ELSE null END,
      i.guncertain2 = CASE WHEN row.guncertain2 IS NOT NULL AND row.guncertain2 <> "" THEN toFloat(row.guncertain2) ELSE null END,
      i.guncertain3 = CASE WHEN row.guncertain3 IS NOT NULL AND row.guncertain3 <> "" THEN toFloat(row.guncertain3) ELSE null END,
      i.nperps = CASE WHEN row.nperps IS NOT NULL AND row.nperps <> "" THEN toFloat(row.nperps) ELSE null END,
      i.nperpcap = CASE WHEN row.nperpcap IS NOT NULL AND row.nperpcap <> "" THEN toFloat(row.nperpcap) ELSE null END,
      i.claimed = CASE WHEN row.claimed IS NOT NULL AND row.claimed <> "" THEN toFloat(row.claimed) ELSE null END,
      i.claimmode = CASE WHEN row.claimmode IS NOT NULL AND row.claimmode <> "" THEN toFloat(row.claimmode) ELSE null END,
      i.claim2 = CASE WHEN row.claim2 IS NOT NULL AND row.claim2 <> "" THEN toFloat(row.claim2) ELSE null END,
      i.claimmode2 = CASE WHEN row.claimmode2 IS NOT NULL AND row.claimmode2 <> "" THEN toFloat(row.claimmode2) ELSE null END,
      i.claim3 = CASE WHEN row.claim3 IS NOT NULL AND row.claim3 <> "" THEN toFloat(row.claim3) ELSE null END,
      i.claimmode3 = CASE WHEN row.claimmode3 IS NOT NULL AND row.claimmode3 <> "" THEN toFloat(row.claimmode3) ELSE null END,
      i.compclaim = CASE WHEN row.compclaim IS NOT NULL AND row.compclaim <> "" THEN toFloat(row.compclaim) ELSE null END,
      i.weapsubtype1 = CASE WHEN row.weapsubtype1 IS NOT NULL AND row.weapsubtype1 <> "" THEN toFloat(row.weapsubtype1) ELSE null END,
      i.weaptype2 = CASE WHEN row.weaptype2 IS NOT NULL AND row.weaptype2 <> "" THEN toFloat(row.weaptype2) ELSE null END,
      i.weapsubtype2 = CASE WHEN row.weapsubtype2 IS NOT NULL AND row.weapsubtype2 <> "" THEN toFloat(row.weapsubtype2) ELSE null END,
      i.weaptype3 = CASE WHEN row.weaptype3 IS NOT NULL AND row.weaptype3 <> "" THEN toFloat(row.weaptype3) ELSE null END,
      i.weapsubtype3 = CASE WHEN row.weapsubtype3 IS NOT NULL AND row.weapsubtype3 <> "" THEN toFloat(row.weapsubtype3) ELSE null END,
      i.weaptype4 = CASE WHEN row.weaptype4 IS NOT NULL AND row.weaptype4 <> "" THEN toFloat(row.weaptype4) ELSE null END,
      i.weapsubtype4 = CASE WHEN row.weapsubtype4 IS NOT NULL AND row.weapsubtype4 <> "" THEN toFloat(row.weapsubtype4) ELSE null END,
      i.nkill = CASE WHEN row.nkill IS NOT NULL AND row.nkill <> "" THEN toFloat(row.nkill) ELSE null END,
      i.nkillus = CASE WHEN row.nkillus IS NOT NULL AND row.nkillus <> "" THEN toFloat(row.nkillus) ELSE null END,
      i.nkillter = CASE WHEN row.nkillter IS NOT NULL AND row.nkillter <> "" THEN toFloat(row.nkillter) ELSE null END,
      i.nwound = CASE WHEN row.nwound IS NOT NULL AND row.nwound <> "" THEN toFloat(row.nwound) ELSE null END,
      i.nwoundus = CASE WHEN row.nwoundus IS NOT NULL AND row.nwoundus <> "" THEN toFloat(row.nwoundus) ELSE null END,
      i.nwoundte = CASE WHEN row.nwoundte IS NOT NULL AND row.nwoundte <> "" THEN toFloat(row.nwoundte) ELSE null END,
      i.propextent = CASE WHEN row.propextent IS NOT NULL AND row.propextent <> "" THEN toFloat(row.propextent) ELSE null END,
      i.propvalue = CASE WHEN row.propvalue IS NOT NULL AND row.propvalue <> "" THEN toFloat(row.propvalue) ELSE null END,
      i.ishostkid = CASE WHEN row.ishostkid IS NOT NULL AND row.ishostkid <> "" THEN toFloat(row.ishostkid) ELSE null END,
      i.nhostkid = CASE WHEN row.nhostkid IS NOT NULL AND row.nhostkid <> "" THEN toFloat(row.nhostkid) ELSE null END,
      i.nhostkidus = CASE WHEN row.nhostkidus IS NOT NULL AND row.nhostkidus <> "" THEN toFloat(row.nhostkidus) ELSE null END,
      i.nhours = CASE WHEN row.nhours IS NOT NULL AND row.nhours <> "" THEN toFloat(row.nhours) ELSE null END,
      i.ndays = CASE WHEN row.ndays IS NOT NULL AND row.ndays <> "" THEN toFloat(row.ndays) ELSE null END,
      i.ransom = CASE WHEN row.ransom IS NOT NULL AND row.ransom <> "" THEN toFloat(row.ransom) ELSE null END,
      i.ransomamt = CASE WHEN row.ransomamt IS NOT NULL AND row.ransomamt <> "" THEN toFloat(row.ransomamt) ELSE null END,
      i.ransomamtus = CASE WHEN row.ransomamtus IS NOT NULL AND row.ransomamtus <> "" THEN toFloat(row.ransomamtus) ELSE null END,
      i.ransompaid = CASE WHEN row.ransompaid IS NOT NULL AND row.ransompaid <> "" THEN toFloat(row.ransompaid) ELSE null END,
      i.ransompaidus = CASE WHEN row.ransompaidus IS NOT NULL AND row.ransompaidus <> "" THEN toFloat(row.ransompaidus) ELSE null END,
      i.hostkidoutcome = CASE WHEN row.hostkidoutcome IS NOT NULL AND row.hostkidoutcome <> "" THEN toFloat(row.hostkidoutcome) ELSE null END,
      i.nreleased = CASE WHEN row.nreleased IS NOT NULL AND row.nreleased <> "" THEN toFloat(row.nreleased) ELSE null END,

      // Object (string) fields
      i.approxdate = row.approxdate,
      i.resolution = row.resolution,
      i.country_txt = row.country_txt,
      i.region_txt = row.region_txt,
      i.provstate = row.provstate,
      i.city = row.city,
      i.location = row.location,
      i.summary = row.summary,
      i.alternative_txt = row.alternative_txt,
      i.attacktype1_txt = row.attacktype1_txt,
      i.attacktype2_txt = row.attacktype2_txt,
      i.attacktype3_txt = row.attacktype3_txt,
      i.targtype1_txt = row.targtype1_txt,
      i.targsubtype1_txt = row.targsubtype1_txt,
      i.corp1 = row.corp1,
      i.target1 = row.target1,
      i.natlty1_txt = row.natlty1_txt,
      i.targtype2_txt = row.targtype2_txt,
      i.targsubtype2_txt = row.targsubtype2_txt,
      i.corp2 = row.corp2,
      i.target2 = row.target2,
      i.natlty2_txt = row.natlty2_txt,
      i.targtype3_txt = row.targtype3_txt,
      i.targsubtype3_txt = row.targsubtype3_txt,
      i.corp3 = row.corp3,
      i.target3 = row.target3,
      i.natlty3_txt = row.natlty3_txt,
      i.gname = row.gname,
      i.gsubname = row.gsubname,
      i.gname2 = row.gname2,
      i.gsubname2 = row.gsubname2,
      i.gname3 = row.gname3,
      i.gsubname3 = row.gsubname3,
      i.motive = row.motive,
      i.claimmode_txt = row.claimmode_txt,
      i.claimmode2_txt = row.claimmode2_txt,
      i.claimmode3_txt = row.claimmode3_txt,
      i.weaptype1_txt = row.weaptype1_txt,
      i.weapsubtype1_txt = row.weapsubtype1_txt,
      i.weaptype2_txt = row.weaptype2_txt,
      i.weapsubtype2_txt = row.weapsubtype2_txt,
      i.weaptype3_txt = row.weaptype3_txt,
      i.weapsubtype3_txt = row.weapsubtype3_txt,
      i.weaptype4_txt = row.weaptype4_txt,
      i.weapsubtype4_txt = row.weapsubtype4_txt,
      i.weapdetail = row.weapdetail,
      i.propextent_txt = row.propextent_txt,
      i.propcomment = row.propcomment,
      i.divert = row.divert,
      i.kidhijcountry = row.kidhijcountry,
      i.ransomnote = row.ransomnote,
      i.hostkidoutcome_txt = row.hostkidoutcome_txt,
      i.addnotes = row.addnotes,
      i.scite1 = row.scite1,
      i.scite2 = row.scite2,
      i.scite3 = row.scite3,
      i.dbsource = row.dbsource,
      i.related = row.related
  ',
  {batchSize: 10, parallel: false}
) YIELD batches, total, operations, failedOperations, retries, errorMessages, batch
RETURN batches, total, operations, failedOperations;
EOF

echo "Data import complete. Query data using the Python script."
