import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
    DynamoDBDocumentClient,
    PutCommand,
    GetCommand,
    QueryCommand,
} from "@aws-sdk/lib-dynamodb";

import middy from "@middy/core";
import httpJsonBodyParser from "@middy/http-json-body-parser";
import httpErrorHandler from "@middy/http-error-handler";
import createError from "http-errors";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { v4 as uuidv4 } from "uuid";

const client = new DynamoDBClient({});
const db = DynamoDBDocumentClient.from(client);

const NOTES_TABLE = process.env.NOTES_TABLE;
const USERS_TABLE = process.env.USERS_TABLE;
const JWT_SECRET = process.env.JWT_SECRET;

function jsonResponse(statusCode, data) {
    return {
        statusCode,
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify(data),
    };
}

// error messages

function validateSignup(body) {
    if (!body || typeof body !== "object") {
        throw new createError.BadRequest("Body must be JSON");
    }

    const { email, password } = body;

    if (!email || typeof email !== "string") {
        throw new createError.BadRequest("email is required");
    }

    if (!password || typeof password !== "string") {
        throw new createError.BadRequest("password is required");
    }

    if (password.length < 6) {
        throw new createError.BadRequest("password must be at least 6 characters");
    }

    return { email: email.trim().toLowerCase(), password };
}

function validateLogin(body) {
    if (!body || typeof body !== "object") {
        throw new createError.BadRequest("Body must be JSON");
    }

    const { email, password } = body;

    if (!email || typeof email !== "string") {
        throw new createError.BadRequest("email is required");
    }

    if (!password || typeof password !== "string") {
        throw new createError.BadRequest("password is required");
    }

    return { email: email.trim().toLowerCase(), password };
}

function validateNoteCreate(body) {
    if (!body || typeof body !== "object") {
        throw new createError.BadRequest("Body must be JSON");
    }

    const { title, text } = body;

    if (!title || typeof title !== "string") {
        throw new createError.BadRequest("title is required");
    }
    if (title.length > 50) {
        throw new createError.BadRequest("title must be max 50 characters");
    }

    if (!text || typeof text !== "string") {
        throw new createError.BadRequest("text is required");
    }
    if (text.length > 300) {
        throw new createError.BadRequest("text must be max 300 characters");
    }

    return {
        title: title.trim(),
        text: text.trim(),
    };
}

function validateNoteUpdate(body) {
    if (!body || typeof body !== "object") {
        throw new createError.BadRequest("Body must be JSON");
    }

    const { id, title, text } = body;

    if (!id || typeof id !== "string") {
        throw new createError.BadRequest("id is required");
    }

    if (!title || typeof title !== "string") {
        throw new createError.BadRequest("title is required");
    }
    if (title.length > 50) {
        throw new createError.BadRequest("title must be max 50 characters");
    }

    if (!text || typeof text !== "string") {
        throw new createError.BadRequest("text is required");
    }
    if (text.length > 300) {
        throw new createError.BadRequest("text must be max 300 characters");
    }

    return {
        id,
        title: title.trim(),
        text: text.trim(),
    };
}

function validateNoteIdOnly(body) {
    if (!body || typeof body !== "object") {
        throw new createError.BadRequest("Body must be JSON");
    }

    const { id } = body;
    if (!id || typeof id !== "string") {
        throw new createError.BadRequest("id is required");
    }

    return { id };
}

// middy auth

const authMiddleware = () => ({
    before: async (request) => {
        const headers = request.event.headers || {};
        const authHeader = headers.authorization || headers.Authorization;

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            throw new createError.Unauthorized("Missing or invalid Authorization header");
        }

        const token = authHeader.slice(7).trim();

        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            request.event.user = decoded;
        } catch (err) {
            console.error("JWT error", err);
            throw new createError.Unauthorized("Invalid or expired token");
        }
    },
});

// POST /api/user/signup
async function signupHandler(event) {
    const { email, password } = validateSignup(event.body);

    const existing = await db.send(
        new GetCommand({
            TableName: USERS_TABLE,
            Key: { email },
        })
    );

    if (existing.Item) {
        throw new createError.BadRequest("User already exists");
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const userId = uuidv4();
    const now = new Date().toISOString();

    await db.send(
        new PutCommand({
            TableName: USERS_TABLE,
            Item: {
                email,
                userId,
                passwordHash,
                createdAt: now,
            },
        })
    );

    return jsonResponse(201, { message: "User created" });
}

// POST /api/user/login
async function loginHandler(event) {
    const { email, password } = validateLogin(event.body);

    const result = await db.send(
        new GetCommand({
            TableName: USERS_TABLE,
            Key: { email },
        })
    );

    if (!result.Item) {
        throw new createError.Unauthorized("Invalid email or password");
    }

    const isMatch = await bcrypt.compare(password, result.Item.passwordHash);
    if (!isMatch) {
        throw new createError.Unauthorized("Invalid email or password");
    }

    const token = jwt.sign(
        { userId: result.Item.userId, email },
        JWT_SECRET,
        { expiresIn: "1h" }
    );

    return jsonResponse(200, { token });
}

// GET /api/notes
async function getNotesHandler(event) {
    const userId = event.user.userId;

    const result = await db.send(
        new QueryCommand({
            TableName: NOTES_TABLE,
            KeyConditionExpression: "userId = :userId",
            ExpressionAttributeValues: {
                ":userId": userId,
            },
        })
    );

    const notes = (result.Items || []).filter((n) => !n.deleted) || [];

    return jsonResponse(200, { notes });
}

// POST /api/notes
async function createNoteHandler(event) {
    const userId = event.user.userId;
    const { title, text } = validateNoteCreate(event.body);

    const now = new Date().toISOString();
    const id = uuidv4();

    const note = {
        userId,
        id,
        title,
        text,
        createdAt: now,
        modifiedAt: now,
    };

    await db.send(
        new PutCommand({
            TableName: NOTES_TABLE,
            Item: note,
        })
    );

    return jsonResponse(201, { note });
}

// PUT /api/notes
async function updateNoteHandler(event) {
    const userId = event.user.userId;
    const { id, title, text } = validateNoteUpdate(event.body);

    const existing = await db.send(
        new GetCommand({
            TableName: NOTES_TABLE,
            Key: { userId, id },
        })
    );

    if (!existing.Item || existing.Item.deleted) {
        throw new createError.NotFound("Note not found");
    }

    const now = new Date().toISOString();

    const updated = {
        ...existing.Item,
        title,
        text,
        modifiedAt: now,
    };

    await db.send(
        new PutCommand({
            TableName: NOTES_TABLE,
            Item: updated,
        })
    );

    return jsonResponse(200, { note: updated });
}

// DELETE /api/notes (recoverable)
async function deleteNoteHandler(event) {
    const userId = event.user.userId;
    const { id } = validateNoteIdOnly(event.body);

    const existing = await db.send(
        new GetCommand({
            TableName: NOTES_TABLE,
            Key: { userId, id },
        })
    );

    if (!existing.Item || existing.Item.deleted) {
        throw new createError.NotFound("Note not found");
    }

    const now = new Date().toISOString();

    const deletedNote = {
        ...existing.Item,
        deleted: true,
        deletedAt: now,
        modifiedAt: now,
    };

    await db.send(
        new PutCommand({
            TableName: NOTES_TABLE,
            Item: deletedNote,
        })
    );

    return jsonResponse(200, { message: "Note deleted", note: deletedNote });
}

// POST /api/notes/restore
async function restoreNoteHandler(event) {
    const userId = event.user.userId;
    const { id } = validateNoteIdOnly(event.body);

    const existing = await db.send(
        new GetCommand({
            TableName: NOTES_TABLE,
            Key: { userId, id },
        })
    );

    if (!existing.Item || !existing.Item.deleted) {
        throw new createError.NotFound("Deleted note not found");
    }

    const now = new Date().toISOString();

    const restoredNote = {
        ...existing.Item,
        deleted: false,
        deletedAt: null,
        modifiedAt: now,
    };

    await db.send(
        new PutCommand({
            TableName: NOTES_TABLE,
            Item: restoredNote,
        })
    );

    return jsonResponse(200, { message: "Note restored", note: restoredNote });
}

// Middy wire handlers

export const signup = middy(signupHandler)
    .use(httpJsonBodyParser())
    .use(httpErrorHandler());

export const login = middy(loginHandler)
    .use(httpJsonBodyParser())
    .use(httpErrorHandler());

export const getNotes = middy(getNotesHandler)
    .use(authMiddleware())
    .use(httpErrorHandler());

export const createNote = middy(createNoteHandler)
    .use(httpJsonBodyParser())
    .use(authMiddleware())
    .use(httpErrorHandler());

export const updateNote = middy(updateNoteHandler)
    .use(httpJsonBodyParser())
    .use(authMiddleware())
    .use(httpErrorHandler());

export const deleteNote = middy(deleteNoteHandler)
    .use(httpJsonBodyParser())
    .use(authMiddleware())
    .use(httpErrorHandler());

export const restoreNote = middy(restoreNoteHandler)
    .use(httpJsonBodyParser())
    .use(authMiddleware())
    .use(httpErrorHandler());