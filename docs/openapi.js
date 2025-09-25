const { OpenAPIRegistry, OpenApiGeneratorV3, extendZodWithOpenApi } = require('@asteasolutions/zod-to-openapi');
const { z } = require('zod');
extendZodWithOpenApi(z);

// Singleton registry
const registry = new OpenAPIRegistry();

// Common schemas
const AuthRegisterSchema = z.object({
    username: z.string().min(3).max(40),
    email: z.string().email(),
    password: z.string().min(6).max(128)
});

const AuthLoginSchema = z.object({
    email: z.string().email(),
    password: z.string().min(1)
});

const ProjectCreateSchema = z.object({
    name: z.string().min(2).max(120),
    description: z.string().min(5).max(2000),
    // Deadline désormais obligatoire pour alignement avec le modèle Mongoose (required: true)
    // Format attendu côté client: ISO string (ex: 2025-09-22T23:59:59.000Z)
    deadline: z.string().min(8, 'Deadline requise'),
    status: z.string().optional(),
    priority: z.string().optional(),
    tags: z.array(z.string()).optional()
});

// Pagination meta schema (used in list responses)
const PaginationMeta = z.object({
    page: z.number(),
    limit: z.number(),
    total: z.number(),
    totalPages: z.number(),
    hasMore: z.boolean()
});
registry.register('PaginationMeta', PaginationMeta);

// Basic list item schemas (lightweight for documentation purposes)
const UserListItem = z.object({
    _id: z.string().optional(),
    username: z.string(),
    email: z.string().email(),
    role: z.string().optional()
});
registry.register('UserListItem', UserListItem);

const TaskListItem = z.object({
    _id: z.string().optional(),
    title: z.string(),
    description: z.string().optional(),
    status: z.string().optional(),
    project: z.string().optional(),
    assignedTo: z.string().optional(),
    priority: z.string().optional(),
    deadline: z.string().optional()
});
registry.register('TaskListItem', TaskListItem);

// === AI Schemas ===
const AIProjectParamSchema = z.object({ projectId: z.string().min(8) });
const AIGenerateSummaryResponse = z.object({
    success: z.boolean(),
    data: z.object({
        id: z.string().optional(),
        project: z.string().optional(),
        summary: z.string().optional(),
        highlights: z.array(z.string()).optional(),
        risks: z.array(z.string()).optional(),
        opportunities: z.array(z.string()).optional()
    }).optional()
});
const AITaskSuggestionsResponse = z.object({
    success: z.boolean(),
    data: z.object({
        id: z.string().optional(),
        project: z.string().optional(),
        suggestions: z.array(z.object({
            title: z.string().optional(),
            description: z.string().optional(),
            priority: z.string().optional(),
            impact: z.string().optional(),
            effort: z.string().optional(),
            rationale: z.string().optional()
        })).optional()
    }).optional()
});
const AIAnalyzeCommentBody = z.object({ taskId: z.string().min(8), commentId: z.string().min(8) });

registry.register('AIProjectParam', AIProjectParamSchema);
registry.register('AIGenerateSummaryResponse', AIGenerateSummaryResponse);
registry.register('AITaskSuggestionsResponse', AITaskSuggestionsResponse);
registry.register('AIAnalyzeCommentBody', AIAnalyzeCommentBody);

// Register schemas with component names
registry.register('AuthRegisterRequest', AuthRegisterSchema);
registry.register('AuthLoginRequest', AuthLoginSchema);
registry.register('ProjectCreateRequest', ProjectCreateSchema);

// Example minimal paths (can be extended later):
registry.registerPath({
    method: 'post',
    path: '/auth/register',
    request: {
        body: {
            content: {
                'application/json': { schema: AuthRegisterSchema }
            }
        }
    },
    responses: {
        201: { description: 'User registered' }
    },
    tags: ['Auth']
});
registry.registerPath({
    method: 'post',
    path: '/auth/login',
    request: {
        body: { content: { 'application/json': { schema: AuthLoginSchema } } }
    },
    responses: { 200: { description: 'Login success / 2FA required' } },
    tags: ['Auth']
});
registry.registerPath({
    method: 'post',
    path: '/projects',
    request: { body: { content: { 'application/json': { schema: ProjectCreateSchema } } } },
    responses: { 201: { description: 'Project created' } },
    tags: ['Projects']
});
// Project list with pagination
registry.registerPath({
    method: 'get',
    path: '/projects',
    request: {
        query: z.object({
            page: z.string().optional(),
            limit: z.string().optional(),
            status: z.string().optional(),
            archived: z.string().optional(),
            q: z.string().optional()
        })
    },
    responses: {
        200: { description: 'Paginated projects', content: { 'application/json': { schema: z.object({ success: z.boolean(), data: z.object({ items: z.array(ProjectCreateSchema.extend({ _id: z.string().optional() })).optional(), meta: PaginationMeta }) }) } } }
    },
    tags: ['Projects'],
    security: [{ bearerAuth: [] }]
});
// Users list with pagination
registry.registerPath({
    method: 'get',
    path: '/users',
    request: {
        query: z.object({
            page: z.string().optional(),
            limit: z.string().optional(),
            role: z.string().optional(),
            q: z.string().optional()
        })
    },
    responses: {
        200: { description: 'Paginated users', content: { 'application/json': { schema: z.object({ success: z.boolean(), data: z.object({ items: z.array(UserListItem).optional(), meta: PaginationMeta }) }) } } }
    },
    tags: ['Users'],
    security: [{ bearerAuth: [] }]
});
// Tasks list with pagination
registry.registerPath({
    method: 'get',
    path: '/tasks',
    request: {
        query: z.object({
            page: z.string().optional(),
            limit: z.string().optional(),
            projectId: z.string().optional(),
            status: z.string().optional(),
            assignedTo: z.string().optional(),
            archived: z.string().optional(),
            q: z.string().optional()
        })
    },
    responses: {
        200: { description: 'Paginated tasks', content: { 'application/json': { schema: z.object({ success: z.boolean(), data: z.object({ items: z.array(TaskListItem).optional(), meta: PaginationMeta }) }) } } }
    },
    tags: ['Tasks'],
    security: [{ bearerAuth: [] }]
});
// AI paths (secured)
registry.registerPath({
    method: 'post',
    path: '/ai/projects/{projectId}/summary',
    request: { params: AIProjectParamSchema },
    responses: { 200: { description: 'Generated summary', content: { 'application/json': { schema: AIGenerateSummaryResponse } } } },
    tags: ['AI'],
    security: [{ bearerAuth: [] }]
});
registry.registerPath({
    method: 'post',
    path: '/ai/projects/{projectId}/suggestions',
    request: { params: AIProjectParamSchema },
    responses: { 200: { description: 'Task suggestions generated', content: { 'application/json': { schema: AITaskSuggestionsResponse } } } },
    tags: ['AI'],
    security: [{ bearerAuth: [] }]
});
registry.registerPath({
    method: 'post',
    path: '/ai/comments/analyze',
    request: { body: { content: { 'application/json': { schema: AIAnalyzeCommentBody } } } },
    responses: { 200: { description: 'Comment analyzed' } },
    tags: ['AI'],
    security: [{ bearerAuth: [] }]
});

// Capabilities endpoint (placeholder, to implement)
const AICapabilitiesResponse = z.object({
    success: z.boolean(),
    data: z.object({
        aiEnabled: z.boolean(),
        model: z.string().nullable(),
        summaryCacheTTLms: z.number(),
        suggestionsCacheTTLms: z.number(),
        rateLimitPerWindow: z.number().optional(),
        windowMinutes: z.number().optional()
    }).optional()
});
registry.register('AICapabilitiesResponse', AICapabilitiesResponse);
registry.registerPath({
    method: 'get',
    path: '/ai/capabilities',
    responses: { 200: { description: 'AI capabilities state', content: { 'application/json': { schema: AICapabilitiesResponse } } } },
    tags: ['AI'],
    security: [{ bearerAuth: [] }]
});

function generateOpenAPIDocument() {
    const generator = new OpenApiGeneratorV3(registry.definitions);
    const baseDoc = generator.generateDocument({
        openapi: '3.0.3',
        info: {
            title: 'DevDash API',
            version: '1.0.0'
        },
        servers: [
            { url: '/api' }
        ],
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT'
                }
            }
        },
        security: [{ bearerAuth: [] }]
    });
    return baseDoc;
}

module.exports = {
    registry,
    AuthRegisterSchema,
    AuthLoginSchema,
    ProjectCreateSchema,
    AIProjectParamSchema,
    AIGenerateSummaryResponse,
    AITaskSuggestionsResponse,
    AIAnalyzeCommentBody,
    AICapabilitiesResponse,
    generateOpenAPIDocument
};
