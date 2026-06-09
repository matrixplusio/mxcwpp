// Package anomaly implements server-side ML anomaly detection.
//
// Core algorithm: Isolation Forest (Liu et al. 2008).
// Input: 13-dimensional BDE behavior snapshots per host.
// Output: anomaly score (0.0 = normal, 1.0 = anomalous).
//
// The forest is periodically retrained from a sliding window of recent samples.
// Between retrains, new samples are scored against the current model.
package anomaly

import (
	"math"
	"math/rand/v2"
	"sync"
)

// IForest is an Isolation Forest model for anomaly detection.
type IForest struct {
	mu    sync.RWMutex
	trees []*iTree
	psi   int     // subsample size used for training
	c     float64 // average path length constant c(psi)
}

// iTree is a single isolation tree.
type iTree struct {
	root *iNode
}

// iNode is a node in an isolation tree.
type iNode struct {
	left, right *iNode
	splitAttr   int     // feature index for split
	splitVal    float64 // split value
	size        int     // number of samples at this node (leaf only)
	height      int     // depth limit reached (leaf)
}

const (
	defaultTrees     = 100 // number of trees
	defaultSubsample = 256 // subsample size per tree
	featureCount     = 13  // BDE snapshot has 13 metrics
)

// NewIForest creates an untrained Isolation Forest.
func NewIForest() *IForest {
	return &IForest{}
}

// Train builds the isolation forest from a matrix of samples.
// Each row is a sample (13 features), at least 32 samples required.
func (f *IForest) Train(data [][]float64) {
	if len(data) < 32 {
		return
	}

	psi := min(defaultSubsample, len(data))

	heightLimit := int(math.Ceil(math.Log2(float64(psi))))
	trees := make([]*iTree, defaultTrees)

	for i := range trees {
		// Subsample without replacement.
		sample := subsample(data, psi)
		trees[i] = &iTree{root: buildTree(sample, 0, heightLimit)}
	}

	f.mu.Lock()
	f.trees = trees
	f.psi = psi
	f.c = avgPathLength(float64(psi))
	f.mu.Unlock()
}

// Trained returns true if the forest has been trained.
func (f *IForest) Trained() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.trees) > 0
}

// Score returns the anomaly score for a sample (0.0 = normal, 1.0 = anomalous).
// Returns -1 if the forest is untrained.
func (f *IForest) Score(sample []float64) float64 {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if len(f.trees) == 0 {
		return -1
	}

	// Average path length across all trees.
	var totalPath float64
	for _, t := range f.trees {
		totalPath += pathLength(sample, t.root, 0)
	}
	avgPath := totalPath / float64(len(f.trees))

	// Anomaly score = 2^(-avgPath / c(psi))
	return math.Pow(2, -avgPath/f.c)
}

// --- Tree construction ---

func buildTree(data [][]float64, currentHeight, heightLimit int) *iNode {
	n := len(data)

	// Base case: leaf node.
	if currentHeight >= heightLimit || n <= 1 {
		return &iNode{size: n, height: currentHeight}
	}

	// Pick random feature and random split value.
	attr := rand.IntN(featureCount)
	minVal, maxVal := featureRange(data, attr)

	if minVal == maxVal {
		// All values identical — can't split.
		return &iNode{size: n, height: currentHeight}
	}

	splitVal := minVal + rand.Float64()*(maxVal-minVal)

	var left, right [][]float64
	for _, row := range data {
		if row[attr] < splitVal {
			left = append(left, row)
		} else {
			right = append(right, row)
		}
	}

	return &iNode{
		splitAttr: attr,
		splitVal:  splitVal,
		left:      buildTree(left, currentHeight+1, heightLimit),
		right:     buildTree(right, currentHeight+1, heightLimit),
	}
}

// pathLength computes the path length for a sample in a tree.
func pathLength(sample []float64, node *iNode, currentHeight int) float64 {
	if node.left == nil && node.right == nil {
		// Leaf: add adjustment for unbuilt subtree.
		return float64(currentHeight) + avgPathLength(float64(node.size))
	}

	if sample[node.splitAttr] < node.splitVal {
		return pathLength(sample, node.left, currentHeight+1)
	}
	return pathLength(sample, node.right, currentHeight+1)
}

// avgPathLength computes c(n), the average path length of an unsuccessful
// search in a Binary Search Tree.
func avgPathLength(n float64) float64 {
	if n <= 1 {
		return 0
	}
	// c(n) = 2*H(n-1) - 2*(n-1)/n, where H(i) = ln(i) + Euler-Mascheroni
	h := math.Log(n-1) + 0.5772156649
	return 2*h - 2*(n-1)/n
}

// --- Utility functions ---

func featureRange(data [][]float64, attr int) (min, max float64) {
	min = data[0][attr]
	max = data[0][attr]
	for _, row := range data[1:] {
		v := row[attr]
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	return
}

func subsample(data [][]float64, n int) [][]float64 {
	if n >= len(data) {
		result := make([][]float64, len(data))
		copy(result, data)
		return result
	}

	// Fisher-Yates partial shuffle.
	indices := make([]int, len(data))
	for i := range indices {
		indices[i] = i
	}
	for i := range n {
		j := i + rand.IntN(len(data)-i)
		indices[i], indices[j] = indices[j], indices[i]
	}

	result := make([][]float64, n)
	for i := range n {
		result[i] = data[indices[i]]
	}
	return result
}
