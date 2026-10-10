/**
 * Demo Mode State Machine Hook
 * 
 * A robust state machine for managing the security demo flow stages.
 * Handles transitions between IDLE → SCANNING → PROCESSING → ENCRYPTING → STORING → SUCCESS
 * Also supports ACCESS flow: IDLE → SCANNING → PROCESSING → MATCHING → ACCESS_RESULT
 */
import { useReducer, useCallback, useEffect, useRef } from 'react';

// Demo states
export const DEMO_STATES = {
    IDLE: 'IDLE',
    SCANNING: 'SCANNING',
    PROCESSING: 'PROCESSING',
    EXTRACTING_FEATURES: 'EXTRACTING_FEATURES',
    ENCRYPTING: 'ENCRYPTING',
    STORING: 'STORING',
    MATCHING: 'MATCHING',
    ACCESS_GRANTED: 'ACCESS_GRANTED',
    ACCESS_DENIED: 'ACCESS_DENIED',
    SUCCESS: 'SUCCESS',
    ERROR: 'ERROR'
};

// Demo actions
export const DEMO_ACTIONS = {
    START_SCAN: 'START_SCAN',
    SCAN_COMPLETE: 'SCAN_COMPLETE',
    START_PROCESSING: 'START_PROCESSING',
    PROCESSING_COMPLETE: 'PROCESSING_COMPLETE',
    START_FEATURE_EXTRACTION: 'START_FEATURE_EXTRACTION',
    FEATURE_EXTRACTION_COMPLETE: 'FEATURE_EXTRACTION_COMPLETE',
    START_ENCRYPTION: 'START_ENCRYPTION',
    ENCRYPTION_COMPLETE: 'ENCRYPTION_COMPLETE',
    START_STORING: 'START_STORING',
    STORING_COMPLETE: 'STORING_COMPLETE',
    START_MATCHING: 'START_MATCHING',
    MATCH_SUCCESS: 'MATCH_SUCCESS',
    MATCH_FAILED: 'MATCH_FAILED',
    SET_ERROR: 'SET_ERROR',
    RESET: 'RESET',
    SET_PROGRESS: 'SET_PROGRESS',
    SET_EMBEDDING: 'SET_EMBEDDING',
    SET_CIPHERTEXT: 'SET_CIPHERTEXT'
};

// Demo flow types
export const DEMO_FLOWS = {
    SETUP: 'SETUP',   // Enroll new identity
    ACCESS: 'ACCESS'  // Verify identity
};

// Initial state
const initialState = {
    currentState: DEMO_STATES.IDLE,
    flow: null,
    progress: 0,
    stageProgress: {},
    embedding: null,
    ciphertext: null,
    matchConfidence: null,
    error: null,
    templateId: null,
    stageTimings: {},
    startTime: null,
    currentStageStartTime: null
};

// Reducer function
function demoReducer(state, action) {
    const now = Date.now();

    switch (action.type) {
        case DEMO_ACTIONS.START_SCAN:
            return {
                ...state,
                currentState: DEMO_STATES.SCANNING,
                flow: action.payload?.flow || DEMO_FLOWS.SETUP,
                progress: 5,
                stageProgress: { scanning: 0 },
                error: null,
                startTime: now,
                currentStageStartTime: now
            };

        case DEMO_ACTIONS.SCAN_COMPLETE:
            return {
                ...state,
                currentState: DEMO_STATES.PROCESSING,
                progress: 15,
                stageProgress: { ...state.stageProgress, scanning: 100, processing: 0 },
                stageTimings: {
                    ...state.stageTimings,
                    scanning: now - state.currentStageStartTime
                },
                currentStageStartTime: now
            };

        case DEMO_ACTIONS.START_PROCESSING:
            return {
                ...state,
                currentState: DEMO_STATES.PROCESSING,
                progress: 20,
                stageProgress: { ...state.stageProgress, processing: 0 }
            };

        case DEMO_ACTIONS.PROCESSING_COMPLETE:
            return {
                ...state,
                progress: 30,
                stageProgress: { ...state.stageProgress, processing: 100 }
            };

        case DEMO_ACTIONS.START_FEATURE_EXTRACTION:
            return {
                ...state,
                currentState: DEMO_STATES.EXTRACTING_FEATURES,
                progress: 35,
                stageProgress: { ...state.stageProgress, featureExtraction: 0 },
                stageTimings: {
                    ...state.stageTimings,
                    processing: now - state.currentStageStartTime
                },
                currentStageStartTime: now
            };

        case DEMO_ACTIONS.FEATURE_EXTRACTION_COMPLETE:
            return {
                ...state,
                progress: 50,
                stageProgress: { ...state.stageProgress, featureExtraction: 100 },
                embedding: action.payload?.embedding,
                stageTimings: {
                    ...state.stageTimings,
                    featureExtraction: now - state.currentStageStartTime
                }
            };

        case DEMO_ACTIONS.SET_EMBEDDING:
            return {
                ...state,
                embedding: action.payload
            };

        case DEMO_ACTIONS.START_ENCRYPTION:
            return {
                ...state,
                currentState: DEMO_STATES.ENCRYPTING,
                progress: 55,
                stageProgress: { ...state.stageProgress, encryption: 0 },
                currentStageStartTime: now
            };

        case DEMO_ACTIONS.ENCRYPTION_COMPLETE:
            return {
                ...state,
                progress: 75,
                stageProgress: { ...state.stageProgress, encryption: 100 },
                ciphertext: action.payload?.ciphertext,
                stageTimings: {
                    ...state.stageTimings,
                    encryption: now - state.currentStageStartTime
                }
            };

        case DEMO_ACTIONS.SET_CIPHERTEXT:
            return {
                ...state,
                ciphertext: action.payload
            };

        case DEMO_ACTIONS.START_STORING:
            return {
                ...state,
                currentState: DEMO_STATES.STORING,
                progress: 80,
                stageProgress: { ...state.stageProgress, storing: 0 },
                currentStageStartTime: now
            };

        case DEMO_ACTIONS.STORING_COMPLETE:
            return {
                ...state,
                currentState: DEMO_STATES.SUCCESS,
                progress: 100,
                stageProgress: { ...state.stageProgress, storing: 100 },
                templateId: action.payload?.templateId,
                stageTimings: {
                    ...state.stageTimings,
                    storing: now - state.currentStageStartTime,
                    total: now - state.startTime
                }
            };

        case DEMO_ACTIONS.START_MATCHING:
            return {
                ...state,
                currentState: DEMO_STATES.MATCHING,
                progress: 80,
                stageProgress: { ...state.stageProgress, matching: 0 },
                currentStageStartTime: now
            };

        case DEMO_ACTIONS.MATCH_SUCCESS:
            return {
                ...state,
                currentState: DEMO_STATES.ACCESS_GRANTED,
                progress: 100,
                stageProgress: { ...state.stageProgress, matching: 100 },
                matchConfidence: action.payload?.confidence,
                stageTimings: {
                    ...state.stageTimings,
                    matching: now - state.currentStageStartTime,
                    total: now - state.startTime
                }
            };

        case DEMO_ACTIONS.MATCH_FAILED:
            return {
                ...state,
                currentState: DEMO_STATES.ACCESS_DENIED,
                progress: 100,
                stageProgress: { ...state.stageProgress, matching: 100 },
                matchConfidence: action.payload?.confidence,
                stageTimings: {
                    ...state.stageTimings,
                    matching: now - state.currentStageStartTime,
                    total: now - state.startTime
                }
            };

        case DEMO_ACTIONS.SET_PROGRESS:
            return {
                ...state,
                progress: action.payload.overall ?? state.progress,
                stageProgress: {
                    ...state.stageProgress,
                    ...action.payload.stages
                }
            };

        case DEMO_ACTIONS.SET_ERROR:
            return {
                ...state,
                currentState: DEMO_STATES.ERROR,
                error: action.payload
            };

        case DEMO_ACTIONS.RESET:
            return initialState;

        default:
            return state;
    }
}

/**
 * Custom hook for managing demo state machine
 */
export function useDemoStateMachine() {
    const [state, dispatch] = useReducer(demoReducer, initialState);
    const animationFrameRef = useRef(null);
    const progressIntervalRef = useRef(null);

    // Cleanup on unmount
    useEffect(() => {
        return () => {
            if (animationFrameRef.current) {
                cancelAnimationFrame(animationFrameRef.current);
            }
            if (progressIntervalRef.current) {
                clearInterval(progressIntervalRef.current);
            }
        };
    }, []);

    // Action creators
    const startScan = useCallback((flow = DEMO_FLOWS.SETUP) => {
        dispatch({ type: DEMO_ACTIONS.START_SCAN, payload: { flow } });
    }, []);

    const completeScan = useCallback(() => {
        dispatch({ type: DEMO_ACTIONS.SCAN_COMPLETE });
    }, []);

    const startProcessing = useCallback(() => {
        dispatch({ type: DEMO_ACTIONS.START_PROCESSING });
    }, []);

    const completeProcessing = useCallback(() => {
        dispatch({ type: DEMO_ACTIONS.PROCESSING_COMPLETE });
    }, []);

    const startFeatureExtraction = useCallback(() => {
        dispatch({ type: DEMO_ACTIONS.START_FEATURE_EXTRACTION });
    }, []);

    const completeFeatureExtraction = useCallback((embedding) => {
        dispatch({ type: DEMO_ACTIONS.FEATURE_EXTRACTION_COMPLETE, payload: { embedding } });
    }, []);

    const setEmbedding = useCallback((embedding) => {
        dispatch({ type: DEMO_ACTIONS.SET_EMBEDDING, payload: embedding });
    }, []);

    const startEncryption = useCallback(() => {
        dispatch({ type: DEMO_ACTIONS.START_ENCRYPTION });
    }, []);

    const completeEncryption = useCallback((ciphertext) => {
        dispatch({ type: DEMO_ACTIONS.ENCRYPTION_COMPLETE, payload: { ciphertext } });
    }, []);

    const setCiphertext = useCallback((ciphertext) => {
        dispatch({ type: DEMO_ACTIONS.SET_CIPHERTEXT, payload: ciphertext });
    }, []);

    const startStoring = useCallback(() => {
        dispatch({ type: DEMO_ACTIONS.START_STORING });
    }, []);

    const completeStoring = useCallback((templateId) => {
        dispatch({ type: DEMO_ACTIONS.STORING_COMPLETE, payload: { templateId } });
    }, []);

    const startMatching = useCallback(() => {
        dispatch({ type: DEMO_ACTIONS.START_MATCHING });
    }, []);

    const matchSuccess = useCallback((confidence) => {
        dispatch({ type: DEMO_ACTIONS.MATCH_SUCCESS, payload: { confidence } });
    }, []);

    const matchFailed = useCallback((confidence) => {
        dispatch({ type: DEMO_ACTIONS.MATCH_FAILED, payload: { confidence } });
    }, []);

    const setProgress = useCallback((overall, stages = {}) => {
        dispatch({ type: DEMO_ACTIONS.SET_PROGRESS, payload: { overall, stages } });
    }, []);

    const setError = useCallback((error) => {
        dispatch({ type: DEMO_ACTIONS.SET_ERROR, payload: error });
    }, []);

    const reset = useCallback(() => {
        dispatch({ type: DEMO_ACTIONS.RESET });
    }, []);

    // Progress animation helper
    const animateProgress = useCallback((stageName, duration, onComplete) => {
        const startTime = Date.now();
        const animate = () => {
            const elapsed = Date.now() - startTime;
            const progress = Math.min((elapsed / duration) * 100, 100);

            dispatch({
                type: DEMO_ACTIONS.SET_PROGRESS,
                payload: { stages: { [stageName]: progress } }
            });

            if (progress < 100) {
                animationFrameRef.current = requestAnimationFrame(animate);
            } else if (onComplete) {
                onComplete();
            }
        };
        animate();
    }, []);

    return {
        state,
        actions: {
            startScan,
            completeScan,
            startProcessing,
            completeProcessing,
            startFeatureExtraction,
            completeFeatureExtraction,
            setEmbedding,
            startEncryption,
            completeEncryption,
            setCiphertext,
            startStoring,
            completeStoring,
            startMatching,
            matchSuccess,
            matchFailed,
            setProgress,
            setError,
            reset,
            animateProgress
        },
        isIdle: state.currentState === DEMO_STATES.IDLE,
        isScanning: state.currentState === DEMO_STATES.SCANNING,
        isProcessing: state.currentState === DEMO_STATES.PROCESSING,
        isExtracting: state.currentState === DEMO_STATES.EXTRACTING_FEATURES,
        isEncrypting: state.currentState === DEMO_STATES.ENCRYPTING,
        isStoring: state.currentState === DEMO_STATES.STORING,
        isMatching: state.currentState === DEMO_STATES.MATCHING,
        isSuccess: state.currentState === DEMO_STATES.SUCCESS,
        isAccessGranted: state.currentState === DEMO_STATES.ACCESS_GRANTED,
        isAccessDenied: state.currentState === DEMO_STATES.ACCESS_DENIED,
        isError: state.currentState === DEMO_STATES.ERROR,
        isComplete: [
            DEMO_STATES.SUCCESS,
            DEMO_STATES.ACCESS_GRANTED,
            DEMO_STATES.ACCESS_DENIED,
            DEMO_STATES.ERROR
        ].includes(state.currentState)
    };
}

export default useDemoStateMachine;
