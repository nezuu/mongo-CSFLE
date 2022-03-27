package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	ctx          = context.Background()
	kmsProviders map[string]map[string]interface{}
)

// データキーの生成
func createDataKey() primitive.Binary {
	// mongoに接続
	kvClient, err := mongo.Connect(ctx, options.Client().ApplyURI("<MONGO_URI>").SetAuth(
		options.Credential{
			Username:   "root",
			Password:   "password",
			AuthSource: "admin",
		}))
	if err != nil {
		panic(err)
	}

	localKey := make([]byte, 96)
	if _, err := rand.Read(localKey); err != nil {
		panic(err)
	}

	kmsProviders = map[string]map[string]interface{}{
		"local": {
			"key": localKey,
		},
	}

	clientEncryptionOpts := options.ClientEncryption().SetKeyVaultNamespace("keyvault.datakeys").SetKmsProviders(kmsProviders)

	// データキー用のdbクライアントを生成
	clientEncryption, err := mongo.NewClientEncryption(kvClient, clientEncryptionOpts)
	if err != nil {
		panic(err)
	}
	defer clientEncryption.Close(ctx)

	// データキーの生成
	dataKeyId, err := clientEncryption.CreateDataKey(ctx, "local", options.DataKey().SetKeyAltNames([]string{"example"}))

	return dataKeyId
}

func readSchemaMap(dataKeyIdBase64 string) bson.M {
	content :=
		`{
			"fle-example.user": {
				"encryptMetadata": {
					"keyId": [
						{
							"$binary": 
								{
									"base64": "%s",
									"subType": "04"
								}
						}
					]
				},
				"properties": {
					"accountNumber": {
						"encrypt": {
							"bsonType": "string",
							"algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
						}
					}
				},
				"bsonType": "object"
			}
		}`
	schema := fmt.Sprintf(content, dataKeyIdBase64)
	var doc bson.M
	if err := bson.UnmarshalExtJSON([]byte(schema), false, &doc); err != nil {
		panic(err)
	}
	return doc
}

// 暗号化用のdbクライアントを生成
func createEncryptedClient(schemaMap bson.M) *mongo.Client {
	mongocryptdOpts := map[string]interface{}{
		"mongodcryptdBypassSpawn": true,
	}

	// 自動暗号化のオプション
	autoEncryptionOpts := options.AutoEncryption().
		SetKeyVaultNamespace("keyvault.datakeys").
		SetKmsProviders(kmsProviders).
		SetSchemaMap(schemaMap).
		SetExtraOptions(mongocryptdOpts)

	// 暗号化用のdbクライアントを生成
	mongoClient, err := mongo.Connect(ctx, options.Client().ApplyURI("<MONGO_URI>").SetAuth(options.Credential{
		Username:   "root",
		Password:   "password",
		AuthSource: "admin",
	}).SetAutoEncryptionOptions(autoEncryptionOpts))
	if err != nil {
		panic(err)
	}

	return mongoClient
}

func main() {
	// データキーの生成
	dataKey := createDataKey()

	// スキーママップを定義
	schemaMap := readSchemaMap(base64.StdEncoding.EncodeToString(dataKey.Data))

	// 暗号化用のdbクライアントを生成
	client := createEncryptedClient(schemaMap)

	defer client.Disconnect(ctx)
	collection := client.Database("fle-example").Collection("user")

	// insert
	if _, err := collection.InsertOne(context.TODO(), bson.M{"name": "TAROOO", "accountNumber": "123456"}); err != nil {
		panic(err)
	}

	// find
	var user interface{}
	err := collection.FindOne(context.TODO(), bson.M{"accountNumber": "123456"}).Decode(&user)
	if err != nil {
		panic(err)
	}
	fmt.Printf("結果:%v", user)
}

// 起動コマンド
// go run -tags cse main.go
