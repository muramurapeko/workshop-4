import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";
import {
  generateRsaKeyPair,
  exportPubKey,
  exportPrvKey,
  importPubKey,
  importPrvKey,
} from "../crypto";

export type Node = { nodeId: number; pubKey: string };

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());

  const nodeRegistry: Node[] = [];

  _registry.post("/registerNode", async (req, res) => {
    const { nodeId, pubKey } = req.body as RegisterNodeBody;

    // Import the public key
    const publicKey = await importPubKey(pubKey);

    const newNode: Node = { nodeId, pubKey };
    nodeRegistry.push(newNode);

    // Export the generated private key
    const privateKey = await generateRsaKeyPair();
    const privateKeyBase64 = await exportPrvKey(privateKey.privateKey);

    res.json({ privateKey: privateKeyBase64 });
  });

  _registry.get("/getPrivateKey", async (req, res) => {
    const { nodeId } = req.query;

    // Generate a new RSA key pair
    const privateKey = await generateRsaKeyPair();

    // Export the private key
    const privateKeyBase64 = await exportPrvKey(privateKey.privateKey);

    res.json({ result: privateKeyBase64 });
  });

  _registry.get("/getNodeRegistry", (req, res) => {
    const response: GetNodeRegistryBody = { nodes: nodeRegistry };
    res.json(response);
  });

  _registry.get("/status", (req, res) => {
    res.send("live");
  });

  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}
