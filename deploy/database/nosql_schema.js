// MongoDB collections schema for SNAPESCAPE NoSQL store

db.createCollection("artifacts", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["scan_id", "type", "data", "created_at"],
      properties: {
        scan_id: { bsonType: "string" },
        type: { bsonType: "string" },
        data: { bsonType: "object" },
        created_at: { bsonType: "date" }
      }
    }
  }
});

db.createCollection("evidence");
db.createCollection("telemetry");
db.createCollection("crawl_paths");
db.createCollection("screenshots");

db.artifacts.createIndex({ scan_id: 1, type: 1 });
db.telemetry.createIndex({ scan_id: 1, created_at: -1 });
db.evidence.createIndex({ finding_id: 1 });
