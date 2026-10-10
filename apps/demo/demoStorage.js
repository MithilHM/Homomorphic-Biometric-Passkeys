/**
 * Demo Storage Service
 * 
 * Manages encrypted embeddings storage for demo mode.
 * Uses localStorage as a simulated database, but can be extended to use
 * Supabase or Firebase for persistent storage.
 */

const STORAGE_KEY = 'fhe_demo_templates';

/**
 * Get all stored templates
 */
export function getAllTemplates() {
    try {
        const stored = localStorage.getItem(STORAGE_KEY);
        return stored ? JSON.parse(stored) : [];
    } catch (e) {
        console.error('Failed to retrieve templates:', e);
        return [];
    }
}

/**
 * Store a new encrypted template
 */
export async function storeTemplate(templateData) {
    const templates = getAllTemplates();

    const newTemplate = {
        id: generateTemplateId(),
        userId: templateData.userId || 'demo-user',
        createdAt: Date.now(),
        updatedAt: Date.now(),
        // Store encrypted ciphertext metadata (not actual ciphertext for demo)
        ciphertext: {
            scheme: templateData.ciphertext?.scheme || 'CKKS',
            size: templateData.ciphertext?.size || 0,
            parmsId: templateData.ciphertext?.parmsId || '',
            preview: templateData.ciphertext?.preview || null
        },
        // Store embedding for demo matching (in production, this would never be stored)
        _demoEmbedding: templateData.embedding ? Array.from(templateData.embedding) : null,
        metadata: {
            deviceInfo: navigator.userAgent,
            sessionId: generateSessionId()
        }
    };

    templates.push(newTemplate);

    try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(templates));
        return { success: true, templateId: newTemplate.id };
    } catch (e) {
        console.error('Failed to store template:', e);
        return { success: false, error: e.message };
    }
}

/**
 * Find matching template by embedding similarity
 */
export function findMatchingTemplate(probeEmbedding, threshold = 0.85) {
    const templates = getAllTemplates();

    if (templates.length === 0) {
        return { found: false, reason: 'No templates enrolled' };
    }

    let bestMatch = null;
    let bestSimilarity = -1;

    for (const template of templates) {
        if (template._demoEmbedding) {
            const similarity = cosineSimilarity(
                probeEmbedding,
                new Float32Array(template._demoEmbedding)
            );

            if (similarity > bestSimilarity) {
                bestSimilarity = similarity;
                bestMatch = template;
            }
        }
    }

    if (bestMatch && bestSimilarity >= threshold) {
        return {
            found: true,
            template: bestMatch,
            similarity: bestSimilarity,
            confidence: bestSimilarity
        };
    }

    return {
        found: false,
        bestSimilarity,
        threshold,
        reason: bestSimilarity >= 0
            ? `Best match (${(bestSimilarity * 100).toFixed(1)}%) below threshold (${(threshold * 100).toFixed(0)}%)`
            : 'No valid embeddings found'
    };
}

/**
 * Delete a template by ID
 */
export function deleteTemplate(templateId) {
    const templates = getAllTemplates();
    const filtered = templates.filter(t => t.id !== templateId);

    try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(filtered));
        return { success: true };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

/**
 * Clear all templates
 */
export function clearAllTemplates() {
    try {
        localStorage.removeItem(STORAGE_KEY);
        return { success: true };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

/**
 * Get template count
 */
export function getTemplateCount() {
    return getAllTemplates().length;
}

/**
 * Get storage stats
 */
export function getStorageStats() {
    const templates = getAllTemplates();
    const storageSize = new Blob([JSON.stringify(templates)]).size;

    return {
        templateCount: templates.length,
        storageUsed: formatBytes(storageSize),
        storageBytes: storageSize,
        lastUpdated: templates.length > 0
            ? Math.max(...templates.map(t => t.updatedAt))
            : null
    };
}

// Helper functions
function generateTemplateId() {
    return 'TPL-' + Date.now().toString(36).toUpperCase() + '-' +
        Math.random().toString(36).substring(2, 8).toUpperCase();
}

function generateSessionId() {
    return 'SES-' + Date.now().toString(36) + Math.random().toString(36).substring(2, 8);
}

function cosineSimilarity(a, b) {
    if (!a || !b || a.length !== b.length) return 0;

    let dot = 0, normA = 0, normB = 0;
    for (let i = 0; i < a.length; i++) {
        dot += a[i] * b[i];
        normA += a[i] * a[i];
        normB += b[i] * b[i];
    }

    return dot / (Math.sqrt(normA) * Math.sqrt(normB) + 1e-10);
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

export default {
    getAllTemplates,
    storeTemplate,
    findMatchingTemplate,
    deleteTemplate,
    clearAllTemplates,
    getTemplateCount,
    getStorageStats
};
