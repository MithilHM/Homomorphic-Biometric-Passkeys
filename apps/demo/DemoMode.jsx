/**
 * Security Demo Mode Component
 * 
 * A high-fidelity demonstration of the biometric authentication flow with:
 * - Animated camera scanning overlay
 * - Visual CNN processing pipeline
 * - Homomorphic encryption visualization
 * - Dual-flow support (Setup & Access)
 */
import React, { useState, useCallback, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useDemoStateMachine, DEMO_FLOWS, DEMO_STATES } from '../hooks/useDemoStateMachine';
import { processFaceWithCNN, getCNNArchitecture, embeddingToVisualization } from '../utils/cnnSimulator';
import { encryptFaceEmbedding, getEncryptionInfo, getCiphertextPreview, CKKS_CONFIG } from '../utils/homomorphicEncryption';
import { storeTemplate, findMatchingTemplate, getStorageStats } from '../utils/demoStorage';
import Button from './Button';
import './DemoMode.css';

// ============================================================================
// Icons
// ============================================================================
const PlayIcon = () => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <polygon points="5 3 19 12 5 21 5 3" />
    </svg>
);

const ShieldCheckIcon = () => (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        <path d="M9 12l2 2 4-4" />
    </svg>
);

const LockIcon = () => (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="3" y="11" width="18" height="11" rx="2" />
        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
);

const UnlockIcon = () => (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="3" y="11" width="18" height="11" rx="2" />
        <path d="M7 11V7a5 5 0 0 1 9.9-1" />
    </svg>
);

const XCircleIcon = () => (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="12" cy="12" r="10" />
        <path d="M15 9l-6 6M9 9l6 6" />
    </svg>
);

const RefreshIcon = () => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M23 4v6h-6M1 20v-6h6" />
        <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
    </svg>
);

const CpuIcon = () => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="4" y="4" width="16" height="16" rx="2" />
        <rect x="9" y="9" width="6" height="6" />
        <path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 15h3M1 9h3M1 15h3" />
    </svg>
);

const DatabaseIcon = () => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <ellipse cx="12" cy="5" rx="9" ry="3" />
        <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3" />
        <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" />
    </svg>
);

// ============================================================================
// Sub-Components
// ============================================================================

/**
 * Camera Scanner with Laser Line Animation
 */
const CameraScanner = ({ isActive, onCapture }) => {
    const videoRef = useRef(null);
    const canvasRef = useRef(null);
    const [hasCamera, setHasCamera] = useState(false);
    const [capturedFrame, setCapturedFrame] = useState(null);

    useEffect(() => {
        if (isActive && !hasCamera) {
            initCamera();
        }
        return () => {
            if (videoRef.current?.srcObject) {
                videoRef.current.srcObject.getTracks().forEach(t => t.stop());
            }
        };
    }, [isActive]);

    const initCamera = async () => {
        try {
            const stream = await navigator.mediaDevices.getUserMedia({
                video: { facingMode: 'user', width: 640, height: 480 }
            });
            if (videoRef.current) {
                videoRef.current.srcObject = stream;
                setHasCamera(true);
            }
        } catch (err) {
            console.error('Camera error:', err);
            setHasCamera(false);
        }
    };

    const captureFrame = useCallback(() => {
        if (!canvasRef.current || !videoRef.current) return;

        const canvas = canvasRef.current;
        const video = videoRef.current;
        canvas.width = video.videoWidth || 640;
        canvas.height = video.videoHeight || 480;

        const ctx = canvas.getContext('2d');
        ctx.drawImage(video, 0, 0);

        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        setCapturedFrame(canvas.toDataURL('image/jpeg', 0.8));

        if (onCapture) {
            onCapture(imageData);
        }
    }, [onCapture]);

    return (
        <div className="camera-scanner-container">
            <div className="camera-viewport">
                {/* Video Feed */}
                <video
                    ref={videoRef}
                    autoPlay
                    playsInline
                    muted
                    className="camera-video"
                />

                {/* Scan Overlay */}
                <div className="scan-overlay-demo">
                    {/* Laser Scan Line */}
                    <motion.div
                        className="laser-scan-line"
                        animate={{
                            top: ['0%', '100%', '0%']
                        }}
                        transition={{
                            duration: 2.5,
                            repeat: Infinity,
                            ease: 'easeInOut'
                        }}
                    />

                    {/* Corner Markers */}
                    <div className="corner-marker top-left" />
                    <div className="corner-marker top-right" />
                    <div className="corner-marker bottom-left" />
                    <div className="corner-marker bottom-right" />

                    {/* Face Detection Zone */}
                    <motion.div
                        className="face-detection-zone"
                        animate={{
                            boxShadow: [
                                '0 0 30px rgba(139, 92, 246, 0.3)',
                                '0 0 60px rgba(16, 185, 129, 0.4)',
                                '0 0 30px rgba(139, 92, 246, 0.3)'
                            ]
                        }}
                        transition={{
                            duration: 2,
                            repeat: Infinity,
                            ease: 'easeInOut'
                        }}
                    />

                    {/* Grid Overlay */}
                    <div className="grid-overlay" />
                </div>

                {/* Status Indicator */}
                <motion.div
                    className="camera-status"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                >
                    <span className="status-dot scanning" />
                    <span>SCANNING</span>
                </motion.div>
            </div>

            {/* Hidden Canvas for Capture */}
            <canvas ref={canvasRef} style={{ display: 'none' }} />

            {/* Capture Button */}
            <motion.button
                className="capture-button"
                onClick={captureFrame}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
            >
                <span className="capture-ring" />
                <span className="capture-center" />
            </motion.button>
        </div>
    );
};

/**
 * Processing Pipeline Stepper
 */
const ProcessingPipeline = ({ stages, currentStage, progress }) => {
    const pipelineStages = [
        { id: 'preprocessing', label: 'Preprocess', icon: '📥' },
        { id: 'conv1', label: 'Conv Block 1', icon: '🔲' },
        { id: 'conv2', label: 'Conv Block 2', icon: '🔳' },
        { id: 'conv3', label: 'Conv Block 3', icon: '⬛' },
        { id: 'dense', label: 'Dense Layer', icon: '🧠' }
    ];

    const getStageStatus = (stageId) => {
        const stageIndex = pipelineStages.findIndex(s => s.id === stageId);
        const currentIndex = pipelineStages.findIndex(s => s.id === currentStage);

        if (stageIndex < currentIndex) return 'complete';
        if (stageIndex === currentIndex) return 'active';
        return 'pending';
    };

    return (
        <div className="processing-pipeline">
            <h4 className="pipeline-title">
                <CpuIcon /> CNN Feature Extraction
            </h4>

            <div className="pipeline-stages">
                {pipelineStages.map((stage, index) => {
                    const status = getStageStatus(stage.id);
                    return (
                        <React.Fragment key={stage.id}>
                            <motion.div
                                className={`pipeline-node ${status}`}
                                initial={{ scale: 0, opacity: 0 }}
                                animate={{ scale: 1, opacity: 1 }}
                                transition={{ delay: index * 0.1 }}
                            >
                                <div className="node-icon">
                                    {status === 'complete' ? '✓' : stage.icon}
                                </div>
                                <span className="node-label">{stage.label}</span>
                                {status === 'active' && (
                                    <motion.div
                                        className="node-progress-ring"
                                        animate={{ rotate: 360 }}
                                        transition={{ duration: 1.5, repeat: Infinity, ease: 'linear' }}
                                    />
                                )}
                            </motion.div>

                            {index < pipelineStages.length - 1 && (
                                <motion.div
                                    className={`pipeline-connector ${status === 'complete' ? 'complete' : ''}`}
                                    initial={{ scaleX: 0 }}
                                    animate={{ scaleX: status === 'complete' ? 1 : 0 }}
                                    transition={{ duration: 0.3 }}
                                />
                            )}
                        </React.Fragment>
                    );
                })}
            </div>

            {/* Feature Map Visualization */}
            <AnimatePresence>
                {currentStage && (
                    <motion.div
                        className="feature-map-preview"
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        exit={{ opacity: 0, height: 0 }}
                    >
                        <div className="feature-map-grid">
                            {Array.from({ length: 8 }).map((_, i) => (
                                <motion.div
                                    key={i}
                                    className="feature-map-cell"
                                    initial={{ opacity: 0 }}
                                    animate={{ opacity: [0.3, 1, 0.3] }}
                                    transition={{
                                        duration: 0.5,
                                        delay: i * 0.05,
                                        repeat: Infinity
                                    }}
                                    style={{
                                        backgroundColor: `hsl(${260 + i * 10}, 70%, ${40 + Math.random() * 30}%)`
                                    }}
                                />
                            ))}
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
};

/**
 * Encryption Visualization
 */
const EncryptionVisualizer = ({ embedding, ciphertext, isEncrypting, progress }) => {
    const embeddingViz = embedding ? embeddingToVisualization(embedding, 8, 16) : null;

    return (
        <div className="encryption-visualizer">
            <h4 className="visualizer-title">
                <LockIcon /> Homomorphic Encryption (CKKS)
            </h4>

            <div className="encryption-flow">
                {/* Raw Embedding */}
                <motion.div
                    className="encryption-stage"
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                >
                    <div className="stage-label">Raw Embedding</div>
                    <div className="embedding-heatmap">
                        {embeddingViz?.map((row, i) => (
                            <div key={i} className="heatmap-row">
                                {row.map((val, j) => (
                                    <motion.div
                                        key={j}
                                        className="heatmap-cell"
                                        initial={{ scale: 0 }}
                                        animate={{ scale: 1 }}
                                        transition={{ delay: (i * 16 + j) * 0.005 }}
                                        style={{
                                            backgroundColor: `rgba(139, 92, 246, ${Math.abs(val)})`
                                        }}
                                    />
                                ))}
                            </div>
                        ))}
                    </div>
                    <div className="stage-info">128-D Vector</div>
                </motion.div>

                {/* Arrow */}
                <motion.div
                    className="encryption-arrow"
                    animate={isEncrypting ? {
                        opacity: [0.5, 1, 0.5],
                        scale: [1, 1.1, 1]
                    } : {}}
                    transition={{ duration: 0.8, repeat: Infinity }}
                >
                    <svg width="60" height="24" viewBox="0 0 60 24">
                        <defs>
                            <linearGradient id="arrowGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                                <stop offset="0%" stopColor="#8b5cf6" />
                                <stop offset="100%" stopColor="#10b981" />
                            </linearGradient>
                        </defs>
                        <path
                            d="M0 12 L45 12 M45 12 L35 4 M45 12 L35 20"
                            stroke="url(#arrowGrad)"
                            strokeWidth="3"
                            fill="none"
                            strokeLinecap="round"
                        />
                    </svg>
                    {isEncrypting && (
                        <motion.div
                            className="encryption-particles"
                            animate={{ x: [0, 60], opacity: [1, 0] }}
                            transition={{ duration: 0.5, repeat: Infinity }}
                        >
                            🔐
                        </motion.div>
                    )}
                </motion.div>

                {/* Ciphertext */}
                <motion.div
                    className="encryption-stage ciphertext"
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: ciphertext ? 1 : 0.3, x: 0 }}
                >
                    <div className="stage-label">CKKS Ciphertext</div>
                    <div className="ciphertext-display">
                        {ciphertext ? (
                            <motion.div
                                className="ciphertext-hex"
                                initial={{ opacity: 0 }}
                                animate={{ opacity: 1 }}
                            >
                                <span className="hex-line">{getCiphertextPreview(ciphertext)?.hex.slice(0, 32) || '...'}</span>
                                <span className="hex-line">{getCiphertextPreview(ciphertext)?.hex.slice(32, 64) || '...'}</span>
                            </motion.div>
                        ) : (
                            <div className="ciphertext-placeholder">
                                <motion.div
                                    animate={{ opacity: [0.3, 0.6, 0.3] }}
                                    transition={{ duration: 1.5, repeat: Infinity }}
                                >
                                    Awaiting encryption...
                                </motion.div>
                            </div>
                        )}
                    </div>
                    <div className="stage-info">
                        {ciphertext ? `${(CKKS_CONFIG.POLY_MODULUS_DEGREE * 2 * 8 / 1024).toFixed(0)} KB` : '—'}
                    </div>
                </motion.div>
            </div>

            {/* Encryption Parameters */}
            <div className="encryption-params">
                <div className="param">
                    <span className="param-label">Scheme</span>
                    <span className="param-value mono">CKKS</span>
                </div>
                <div className="param">
                    <span className="param-label">Security</span>
                    <span className="param-value mono">128-bit</span>
                </div>
                <div className="param">
                    <span className="param-label">Poly Degree</span>
                    <span className="param-value mono">8192</span>
                </div>
                <div className="param">
                    <span className="param-label">Scale</span>
                    <span className="param-value mono">2<sup>40</sup></span>
                </div>
            </div>

            {/* Progress Bar */}
            {isEncrypting && (
                <motion.div
                    className="encryption-progress"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                >
                    <div className="progress-bar">
                        <motion.div
                            className="progress-fill"
                            initial={{ width: 0 }}
                            animate={{ width: `${progress}%` }}
                            transition={{ duration: 0.3 }}
                        />
                    </div>
                    <span className="progress-text">{progress.toFixed(0)}%</span>
                </motion.div>
            )}
        </div>
    );
};

/**
 * Result Display
 */
const ResultDisplay = ({ isSuccess, isAccessGranted, isAccessDenied, templateId, confidence, timings, onReset }) => {
    const isPositive = isSuccess || isAccessGranted;

    return (
        <motion.div
            className={`result-display ${isPositive ? 'success' : 'denied'}`}
            initial={{ scale: 0.8, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ type: 'spring', stiffness: 200 }}
        >
            <motion.div
                className="result-icon"
                initial={{ rotate: -180, scale: 0 }}
                animate={{ rotate: 0, scale: 1 }}
                transition={{ type: 'spring', stiffness: 200, delay: 0.2 }}
            >
                {isSuccess && <ShieldCheckIcon />}
                {isAccessGranted && <UnlockIcon />}
                {isAccessDenied && <XCircleIcon />}
            </motion.div>

            <motion.h3
                className="result-title"
                initial={{ y: 20, opacity: 0 }}
                animate={{ y: 0, opacity: 1 }}
                transition={{ delay: 0.3 }}
            >
                {isSuccess && 'Identity Secured!'}
                {isAccessGranted && 'Access Granted'}
                {isAccessDenied && 'Access Denied'}
            </motion.h3>

            <motion.div
                className="result-details"
                initial={{ y: 20, opacity: 0 }}
                animate={{ y: 0, opacity: 1 }}
                transition={{ delay: 0.4 }}
            >
                {templateId && (
                    <div className="result-item">
                        <span>Template ID</span>
                        <span className="mono">{templateId}</span>
                    </div>
                )}
                {confidence !== null && (
                    <div className="result-item">
                        <span>Match Confidence</span>
                        <span className="mono">{(confidence * 100).toFixed(1)}%</span>
                    </div>
                )}
                {timings?.total && (
                    <div className="result-item">
                        <span>Total Time</span>
                        <span className="mono">{(timings.total / 1000).toFixed(2)}s</span>
                    </div>
                )}
            </motion.div>

            <motion.div
                initial={{ y: 20, opacity: 0 }}
                animate={{ y: 0, opacity: 1 }}
                transition={{ delay: 0.5 }}
            >
                <Button variant="ghost" onClick={onReset} icon={<RefreshIcon />}>
                    Run Again
                </Button>
            </motion.div>
        </motion.div>
    );
};

// ============================================================================
// Main Demo Mode Component
// ============================================================================
const DemoMode = ({ onClose }) => {
    const [selectedFlow, setSelectedFlow] = useState(null);
    const [showCamera, setShowCamera] = useState(false);
    const [capturedImageData, setCapturedImageData] = useState(null);
    const [cnnStage, setCnnStage] = useState(null);
    const [cnnProgress, setCnnProgress] = useState(0);
    const [encryptionProgress, setEncryptionProgress] = useState(0);

    const demoMachine = useDemoStateMachine();
    const { state, actions } = demoMachine;

    const storageStats = getStorageStats();

    // Start Demo Flow
    const startFlow = useCallback((flowType) => {
        setSelectedFlow(flowType);
        setShowCamera(true);
        actions.startScan(flowType);
    }, [actions]);

    // Handle captured image
    const handleCapture = useCallback(async (imageData) => {
        setCapturedImageData(imageData);
        setShowCamera(false);
        actions.completeScan();

        // Start CNN processing
        actions.startFeatureExtraction();

        try {
            // Process with CNN
            const cnnResult = await processFaceWithCNN(imageData, (progress) => {
                setCnnStage(progress.stage);
                setCnnProgress(progress.progress);
            });

            const embedding = cnnResult.embedding;
            actions.completeFeatureExtraction(embedding);

            // Start encryption
            actions.startEncryption();

            const encryptionResult = await encryptFaceEmbedding(embedding, (progress) => {
                setEncryptionProgress(progress.progress);
            });

            actions.completeEncryption(encryptionResult.ciphertext);

            if (selectedFlow === DEMO_FLOWS.SETUP) {
                // Setup flow: Store the template
                actions.startStoring();

                const storeResult = await storeTemplate({
                    embedding,
                    ciphertext: encryptionResult.ciphertext
                });

                if (storeResult.success) {
                    actions.completeStoring(storeResult.templateId);
                } else {
                    actions.setError('Failed to store template');
                }
            } else {
                // Access flow: Match against stored templates
                actions.startMatching();

                await new Promise(resolve => setTimeout(resolve, 1000)); // Simulate matching time

                const matchResult = findMatchingTemplate(embedding);

                if (matchResult.found) {
                    actions.matchSuccess(matchResult.confidence);
                } else {
                    actions.matchFailed(matchResult.bestSimilarity || 0);
                }
            }
        } catch (error) {
            console.error('Demo flow error:', error);
            actions.setError(error.message);
        }
    }, [selectedFlow, actions]);

    // Reset demo
    const resetDemo = useCallback(() => {
        setSelectedFlow(null);
        setShowCamera(false);
        setCapturedImageData(null);
        setCnnStage(null);
        setCnnProgress(0);
        setEncryptionProgress(0);
        actions.reset();
    }, [actions]);

    // Render flow selection
    if (!selectedFlow) {
        return (
            <motion.div
                className="demo-mode-container"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
            >
                <div className="demo-header">
                    <h2 className="demo-title">
                        <ShieldCheckIcon /> Security Demo Mode
                    </h2>
                    <p className="demo-subtitle">
                        Experience privacy-preserving biometric authentication in action
                    </p>
                </div>

                <div className="flow-selection">
                    <motion.div
                        className="flow-card setup"
                        whileHover={{ scale: 1.02, y: -5 }}
                        whileTap={{ scale: 0.98 }}
                        onClick={() => startFlow(DEMO_FLOWS.SETUP)}
                    >
                        <div className="flow-icon">👤</div>
                        <h3>Setup Flow</h3>
                        <p>Enroll a new identity</p>
                        <div className="flow-steps">
                            <span>Scan</span>
                            <span>→</span>
                            <span>CNN</span>
                            <span>→</span>
                            <span>Encrypt</span>
                            <span>→</span>
                            <span>Store</span>
                        </div>
                        <Button variant="primary">Start Enrollment</Button>
                    </motion.div>

                    <motion.div
                        className="flow-card access"
                        whileHover={{ scale: 1.02, y: -5 }}
                        whileTap={{ scale: 0.98 }}
                        onClick={() => startFlow(DEMO_FLOWS.ACCESS)}
                    >
                        <div className="flow-icon">🔐</div>
                        <h3>Access Flow</h3>
                        <p>Verify your identity</p>
                        <div className="flow-steps">
                            <span>Scan</span>
                            <span>→</span>
                            <span>CNN</span>
                            <span>→</span>
                            <span>Match</span>
                            <span>→</span>
                            <span>Result</span>
                        </div>
                        <Button variant="secondary">Start Verification</Button>
                    </motion.div>
                </div>

                {/* Storage Stats */}
                <div className="storage-info">
                    <DatabaseIcon />
                    <span>
                        {storageStats.templateCount} template{storageStats.templateCount !== 1 ? 's' : ''} stored
                        ({storageStats.storageUsed})
                    </span>
                </div>

                {onClose && (
                    <Button variant="ghost" onClick={onClose} style={{ marginTop: '1rem' }}>
                        Close Demo
                    </Button>
                )}
            </motion.div>
        );
    }

    // Render active demo flow
    return (
        <motion.div
            className="demo-mode-container active"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
        >
            {/* Progress Header */}
            <div className="demo-progress-header">
                <div className="flow-indicator">
                    {selectedFlow === DEMO_FLOWS.SETUP ? '👤 Setup Flow' : '🔐 Access Flow'}
                </div>
                <div className="overall-progress">
                    <div className="progress-bar-mini">
                        <motion.div
                            className="progress-fill-mini"
                            animate={{ width: `${state.progress}%` }}
                        />
                    </div>
                    <span>{state.progress.toFixed(0)}%</span>
                </div>
            </div>

            {/* Stage Content */}
            <AnimatePresence mode="wait">
                {/* Camera Stage */}
                {showCamera && (
                    <motion.div
                        key="camera"
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -20 }}
                    >
                        <CameraScanner
                            isActive={showCamera}
                            onCapture={handleCapture}
                        />
                    </motion.div>
                )}

                {/* Processing Stage */}
                {(demoMachine.isExtracting || demoMachine.isProcessing) && (
                    <motion.div
                        key="processing"
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -20 }}
                    >
                        <ProcessingPipeline
                            stages={[]}
                            currentStage={cnnStage}
                            progress={cnnProgress}
                        />
                    </motion.div>
                )}

                {/* Encryption Stage */}
                {(demoMachine.isEncrypting || demoMachine.isStoring || demoMachine.isMatching) && (
                    <motion.div
                        key="encryption"
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -20 }}
                    >
                        <EncryptionVisualizer
                            embedding={state.embedding}
                            ciphertext={state.ciphertext}
                            isEncrypting={demoMachine.isEncrypting}
                            progress={encryptionProgress}
                        />
                    </motion.div>
                )}

                {/* Result Stage */}
                {demoMachine.isComplete && (
                    <motion.div
                        key="result"
                        initial={{ opacity: 0, scale: 0.9 }}
                        animate={{ opacity: 1, scale: 1 }}
                    >
                        <ResultDisplay
                            isSuccess={demoMachine.isSuccess}
                            isAccessGranted={demoMachine.isAccessGranted}
                            isAccessDenied={demoMachine.isAccessDenied}
                            templateId={state.templateId}
                            confidence={state.matchConfidence}
                            timings={state.stageTimings}
                            onReset={resetDemo}
                        />
                    </motion.div>
                )}
            </AnimatePresence>

            {/* Cancel Button */}
            {!demoMachine.isComplete && (
                <Button
                    variant="ghost"
                    onClick={resetDemo}
                    style={{ marginTop: '2rem' }}
                >
                    Cancel Demo
                </Button>
            )}
        </motion.div>
    );
};

export default DemoMode;
