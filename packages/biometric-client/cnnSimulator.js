/**
 * CNN Simulator - Lightweight CNN Face Embedding Generation
 * 
 * Simulates a Convolutional Neural Network that processes face images
 * and outputs a 128-dimensional embedding vector.
 * 
 * Architecture simulated:
 * Input → Conv2D → ReLU → MaxPool → Conv2D → ReLU → MaxPool → 
 * Conv2D → ReLU → Flatten → Dense → Dense (128-D Embedding)
 */

// Configuration for CNN simulation
const CNN_CONFIG = {
    EMBEDDING_DIM: 128,
    CONV_LAYERS: 3,
    FEATURE_MAP_SIZES: [64, 128, 256],
    KERNEL_SIZE: 3,
    POOL_SIZE: 2,
    DENSE_LAYERS: [512, 256, 128]
};

/**
 * Simulate convolution operation visualization data
 */
function simulateConvLayer(inputSize, kernelSize, numFilters) {
    const outputSize = inputSize - kernelSize + 1;
    return {
        inputSize,
        outputSize,
        numFilters,
        operations: inputSize * inputSize * kernelSize * kernelSize * numFilters,
        featureMapPreview: Array.from({ length: Math.min(numFilters, 8) }, () =>
            Array.from({ length: 8 }, () =>
                Array.from({ length: 8 }, () => Math.random())
            )
        )
    };
}

/**
 * Simulate ReLU activation
 */
function simulateReLU(values) {
    return values.map(v => Math.max(0, v));
}

/**
 * Simulate max pooling visualization
 */
function simulateMaxPool(inputSize, poolSize) {
    return Math.floor(inputSize / poolSize);
}

/**
 * Generate pseudo-random embedding from image data
 * Uses a deterministic hash-like function to ensure same image produces similar embeddings
 */
function generateEmbeddingFromImageData(imageData) {
    const data = imageData?.data || new Uint8Array(128);
    const embedding = new Float32Array(CNN_CONFIG.EMBEDDING_DIM);

    // Sample pixels strategically across the image
    const step = Math.max(1, Math.floor(data.length / (CNN_CONFIG.EMBEDDING_DIM * 4)));

    for (let i = 0; i < CNN_CONFIG.EMBEDDING_DIM; i++) {
        // Combine multiple pixel values for each embedding dimension
        let value = 0;
        for (let j = 0; j < 4; j++) {
            const idx = ((i * 4 + j) * step) % data.length;
            value += data[idx] / 255;
        }
        // Apply non-linearity and normalization
        embedding[i] = Math.tanh((value / 4 - 0.5) * 3);
    }

    // L2 normalize the embedding
    const norm = Math.sqrt(embedding.reduce((sum, v) => sum + v * v, 0));
    for (let i = 0; i < embedding.length; i++) {
        embedding[i] = embedding[i] / (norm + 1e-10);
    }

    return embedding;
}

/**
 * Generate random embedding for demo purposes
 */
function generateRandomEmbedding() {
    const embedding = new Float32Array(CNN_CONFIG.EMBEDDING_DIM);

    for (let i = 0; i < CNN_CONFIG.EMBEDDING_DIM; i++) {
        // Generate values following roughly normal distribution
        const u1 = Math.random();
        const u2 = Math.random();
        embedding[i] = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
    }

    // L2 normalize
    const norm = Math.sqrt(embedding.reduce((sum, v) => sum + v * v, 0));
    for (let i = 0; i < embedding.length; i++) {
        embedding[i] = embedding[i] / (norm + 1e-10);
    }

    return embedding;
}

/**
 * CNN Processing Pipeline with progress callbacks
 */
export async function processFaceWithCNN(imageData, onProgress) {
    const results = {
        stages: [],
        embedding: null,
        featureMaps: [],
        timing: {}
    };

    const startTime = performance.now();

    // Stage 1: Preprocessing
    if (onProgress) onProgress({ stage: 'preprocessing', progress: 0, message: 'Normalizing input image...' });
    await simulateDelay(300);
    results.stages.push({
        name: 'Preprocessing',
        description: 'Image normalization and resizing to 224×224',
        inputShape: [224, 224, 3],
        outputShape: [224, 224, 3],
        duration: 120
    });
    if (onProgress) onProgress({ stage: 'preprocessing', progress: 100, message: 'Input normalized' });

    // Stage 2: Conv Layer 1
    if (onProgress) onProgress({ stage: 'conv1', progress: 0, message: 'Applying Conv2D + ReLU...' });
    await simulateDelay(400);
    const conv1 = simulateConvLayer(224, CNN_CONFIG.KERNEL_SIZE, CNN_CONFIG.FEATURE_MAP_SIZES[0]);
    results.stages.push({
        name: 'Conv2D Block 1',
        description: `${CNN_CONFIG.FEATURE_MAP_SIZES[0]} filters, ${CNN_CONFIG.KERNEL_SIZE}×${CNN_CONFIG.KERNEL_SIZE} kernel`,
        inputShape: [224, 224, 3],
        outputShape: [111, 111, 64],
        operations: conv1.operations,
        activation: 'ReLU',
        pooling: 'MaxPool2D (2×2)'
    });
    results.featureMaps.push(conv1.featureMapPreview);
    if (onProgress) onProgress({ stage: 'conv1', progress: 100, message: 'Conv Block 1 complete' });

    // Stage 3: Conv Layer 2
    if (onProgress) onProgress({ stage: 'conv2', progress: 0, message: 'Deep feature extraction...' });
    await simulateDelay(350);
    const conv2 = simulateConvLayer(111, CNN_CONFIG.KERNEL_SIZE, CNN_CONFIG.FEATURE_MAP_SIZES[1]);
    results.stages.push({
        name: 'Conv2D Block 2',
        description: `${CNN_CONFIG.FEATURE_MAP_SIZES[1]} filters with batch normalization`,
        inputShape: [111, 111, 64],
        outputShape: [54, 54, 128],
        operations: conv2.operations,
        activation: 'ReLU',
        pooling: 'MaxPool2D (2×2)'
    });
    results.featureMaps.push(conv2.featureMapPreview);
    if (onProgress) onProgress({ stage: 'conv2', progress: 100, message: 'Conv Block 2 complete' });

    // Stage 4: Conv Layer 3
    if (onProgress) onProgress({ stage: 'conv3', progress: 0, message: 'High-level feature extraction...' });
    await simulateDelay(350);
    const conv3 = simulateConvLayer(54, CNN_CONFIG.KERNEL_SIZE, CNN_CONFIG.FEATURE_MAP_SIZES[2]);
    results.stages.push({
        name: 'Conv2D Block 3',
        description: `${CNN_CONFIG.FEATURE_MAP_SIZES[2]} filters, residual connections`,
        inputShape: [54, 54, 128],
        outputShape: [26, 26, 256],
        operations: conv3.operations,
        activation: 'ReLU',
        pooling: 'GlobalAveragePool2D'
    });
    results.featureMaps.push(conv3.featureMapPreview);
    if (onProgress) onProgress({ stage: 'conv3', progress: 100, message: 'Feature extraction complete' });

    // Stage 5: Flatten + Dense layers
    if (onProgress) onProgress({ stage: 'dense', progress: 0, message: 'Computing embedding vector...' });
    await simulateDelay(300);
    results.stages.push({
        name: 'Dense Network',
        description: 'Fully connected layers: 512 → 256 → 128',
        inputShape: [256],
        outputShape: [128],
        layers: CNN_CONFIG.DENSE_LAYERS
    });
    if (onProgress) onProgress({ stage: 'dense', progress: 50, message: 'Dense layer processing...' });

    await simulateDelay(200);

    // Generate the embedding
    if (imageData) {
        results.embedding = generateEmbeddingFromImageData(imageData);
    } else {
        results.embedding = generateRandomEmbedding();
    }

    if (onProgress) onProgress({ stage: 'dense', progress: 100, message: 'Embedding generated' });

    results.timing.total = performance.now() - startTime;
    results.timing.perStage = results.stages.map((s, i) => ({
        name: s.name,
        duration: [120, 400, 350, 350, 300][i]
    }));

    return results;
}

/**
 * Calculate cosine similarity between two embeddings
 */
export function cosineSimilarity(embedding1, embedding2) {
    if (!embedding1 || !embedding2 || embedding1.length !== embedding2.length) {
        return 0;
    }

    let dotProduct = 0;
    let norm1 = 0;
    let norm2 = 0;

    for (let i = 0; i < embedding1.length; i++) {
        dotProduct += embedding1[i] * embedding2[i];
        norm1 += embedding1[i] * embedding1[i];
        norm2 += embedding2[i] * embedding2[i];
    }

    return dotProduct / (Math.sqrt(norm1) * Math.sqrt(norm2) + 1e-10);
}

/**
 * Visualize embedding as a heatmap-compatible array
 */
export function embeddingToVisualization(embedding, rows = 8, cols = 16) {
    const visual = [];
    for (let i = 0; i < rows; i++) {
        const row = [];
        for (let j = 0; j < cols; j++) {
            const idx = i * cols + j;
            row.push(idx < embedding.length ? embedding[idx] : 0);
        }
        visual.push(row);
    }
    return visual;
}

/**
 * Get CNN architecture info for visualization
 */
export function getCNNArchitecture() {
    return {
        name: 'FaceNet-Lite',
        totalParams: '2.4M',
        layers: [
            { type: 'Input', shape: [224, 224, 3], color: '#8b5cf6' },
            { type: 'Conv2D', filters: 64, kernel: [3, 3], color: '#06b6d4' },
            { type: 'MaxPool2D', pool: [2, 2], color: '#10b981' },
            { type: 'Conv2D', filters: 128, kernel: [3, 3], color: '#06b6d4' },
            { type: 'MaxPool2D', pool: [2, 2], color: '#10b981' },
            { type: 'Conv2D', filters: 256, kernel: [3, 3], color: '#06b6d4' },
            { type: 'GlobalAvgPool', color: '#10b981' },
            { type: 'Dense', units: 512, activation: 'ReLU', color: '#f472b6' },
            { type: 'Dense', units: 256, activation: 'ReLU', color: '#f472b6' },
            { type: 'Dense', units: 128, activation: 'L2Norm', color: '#f59e0b' }
        ],
        embeddingDim: CNN_CONFIG.EMBEDDING_DIM
    };
}

// Helper function to simulate processing delay
function simulateDelay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

export default {
    processFaceWithCNN,
    cosineSimilarity,
    embeddingToVisualization,
    getCNNArchitecture,
    generateRandomEmbedding,
    CNN_CONFIG
};
