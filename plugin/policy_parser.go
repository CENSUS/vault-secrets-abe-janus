package abe

import (
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/Nik-U/pbc"
)

type node struct {
	val       string
	dup_label int
	parent    *node
	left      *node
	right     *node
}

//val (default="-")is either the optype or attribute (if the node is a leaf)
//dup_label (default=0) is the duplicate index 0 means it is unique, 1 means it isn't unique and that this is the first instance
//parent (default=nil) is a pointer to the parent node
//left (default=nil) is a pointer to the left child node
//right (default=nil) is a pointer to the right child node

func createPolicy(policy_str string) (tree_root node) {

	tokenized := tokenize(policy_str)

	//Check to see if the tree will only be 1 leaf without nodes

	if oneleaftreecheck(tokenized) {

		tree_root = oneleaftree(tokenized)

	} else {

		tree_root = to_tree(tokenized)
	}

	dup_dict := make(map[string]int)

	find_dups(dup_dict, &tree_root)

	//dup_label starts at 1
	label_dups(dup_dict, &tree_root)

	return
}

func tokenize(in string) []string {

	var s []string
	space := regexp.MustCompile(`\s+`)

	in = strings.ToUpper(in)
	in = strings.Replace(in, "(", "( ", -1)
	in = strings.Replace(in, ")", " )", -1)
	in = space.ReplaceAllString(in, " ")
	out := strings.Split(in, " ")

	for i := 0; i < len(out); i++ {

		s = append(s, string(out[i]))
	}

	return s
}

func isOp(in string) bool {

	return ((in == "AND") || (in == "OR"))

}

func isOpOr(in string) bool {

	return (in == "OR")
}

func isOpAnd(in string) bool {

	return (in == "AND")
}

func isLPar(in string) bool {

	return (in == "(")

}

func isRPar(in string) bool {

	return (in == ")")

}

func isAttr(in string) bool {

	return (!isOp(in) && !isRPar(in) && !isLPar(in))

}

func to_tree(in []string) node {

	root_node := node{"-", 0, nil, nil, nil}
	root_node.parent = &root_node

	current_node := &root_node

	i := 0
	for i < len(in) {

		if isLPar(string(in[i])) {
			// Create child node move and move down
			if (*current_node).left == nil {
				(*current_node).left = &node{"-", 0, current_node, nil, nil}
				current_node = (*current_node).left
			} else {
				(*current_node).right = &node{"-", 0, current_node, nil, nil}
				current_node = (*current_node).right
			}
		} else if isRPar(string(in[i])) {
			// Move up
			current_node = (*current_node).parent
		} else if isAttr(string(in[i])) {
			// Create leaf node but do not enter the leaf
			if (*current_node).left == nil {
				(*current_node).left = &node{string(in[i]), 0, current_node, nil, nil}
			} else {
				(*current_node).right = &node{string(in[i]), 0, current_node, nil, nil}
			}
		} else if isOp(string(in[i])) {
			// Set node op but do not move
			(*current_node).val = string(in[i])
		}

		i++
	}

	return root_node
}

func oneleaftreecheck(in []string) (result bool) {
	total := 0
	result = false
	for _, v := range in {
		if !isLPar(v) && !isRPar(v) {
			total += 1
		}
	}
	if total == 1 {
		result = true
	}
	return
}

func oneleaftree(in []string) node {

	root_node := node{"-", 0, nil, nil, nil}
	for i, v := range in {
		if !isLPar(v) && !isRPar(v) {
			root_node.val = in[i]
			root_node.parent = &root_node
			break
		}
	}
	return root_node
}

func find_dups(dict map[string]int, current_node *node) {
	// Go left
	if (*current_node).left != nil {
		find_dups(dict, (*current_node).left)
	}
	// Go right
	if (*current_node).right != nil {
		find_dups(dict, (*current_node).right)
	}

	if isAttr((*current_node).val) {

		if dict[(*current_node).val] == 0 {
			dict[(*current_node).val] = 1
		} else {
			dict[(*current_node).val] += 1
		}
	}
}

func label_dups(dict map[string]int, current_node *node) {

	label_dict := make(map[string]int)

	// Mark Keys for Labeling
	for k, v := range dict {
		if v > 1 {
			label_dict[k] = 1
		}
	}

	label_node(label_dict, current_node)

}

func label_node(dict map[string]int, current_node *node) {
	// Go left
	if (*current_node).left != nil {
		label_node(dict, (*current_node).left)
	}
	// Go right
	if (*current_node).right != nil {
		label_node(dict, (*current_node).right)
	}

	if isAttr((*current_node).val) {

		if dict[(*current_node).val] != 0 {
			(*current_node).dup_label = dict[(*current_node).val]
			dict[(*current_node).val] += 1
		}
	}
}

func (root *node) calculateSharesList(pairing *pbc.Element, s *pbc.Element, attr_list map[string]*pbc.Element) {

	root.compute_shares(pairing, s, attr_list)
}

func (subtree *node) compute_shares(pairing *pbc.Element, s *pbc.Element, attr_list map[string]*pbc.Element) {

	// k is the threshold 1-of-2 (OR) or 2-of-2 (AND nodes)
	k := 0

	// Empty Node
	if subtree == nil {
		return
	}
	// Leaf Node
	if !isOp((*subtree).val) {
		attr := (*subtree).val
		if (*subtree).dup_label > 0 {
			attr = fmt.Sprintf("%s_%d", attr, (*subtree).dup_label-1)
		}
		attr_list[attr] = s
		return
		// Operator Node
	} else if isOpOr((*subtree).val) {
		k = 1
	} else if isOpAnd((*subtree).val) {
		k = 2
		// Invalid catch
	} else {
		return
	}

	// Generate shares
	shares := genshares(pairing, s, k, 2)

	// Recurse
	(*subtree).left.compute_shares(pairing, shares[1], attr_list)
	(*subtree).right.compute_shares(pairing, shares[2], attr_list)
}

func genshares(pairing *pbc.Element, s *pbc.Element, k int, n int) (shares []*pbc.Element) {
	if k <= n {

		// New Random secret
		new_s := pairing.Pairing().NewZr().Rand()

		var a []*pbc.Element
		for i := 0; i < k; i++ {
			if i == 0 {
				a = append(a, s)
			} else {
				a = append(a, new_s)
			}
		}
		for j := 0; j < (n + 1); j++ {
			shares = append(shares, Pfunc(a, j, pairing))
		}
	}
	return
}

func Pfunc(coeff []*pbc.Element, x int, pairing *pbc.Element) (out_share *pbc.Element) {
	// set to 0
	out_share = pairing.Pairing().NewZr().Set0()
	// Evaluate Polynomial
	for i := 0; i < len(coeff); i++ {

		res := pairing.Pairing().NewZr().Rand()
		res.MulInt32(coeff[i], powInt(x, i))
		out_share.Add(out_share, res)
	}
	return
}

func powInt(x, y int) int32 {
	return int32(math.Pow(float64(x), float64(y)))
}

func (subtree *node) getAttributeTraverse(aList *[]string) {

	// Empty Node
	if subtree == nil {
		return
	}
	// Leaf Node
	if !isOp((*subtree).val) {
		attr := (*subtree).val
		if (*subtree).dup_label > 0 {
			attr = fmt.Sprintf("%s_%d", attr, (*subtree).dup_label-1)
		}
		(*aList) = append((*aList), attr)
	} else {
		// Recurse
		(*subtree).left.getAttributeTraverse(aList)
		(*subtree).right.getAttributeTraverse(aList)
	}

	return
}

func (root *node) getAttributeList() (aList []string) {
	root.getAttributeTraverse(&aList)
	return
}

func (root *node) getCoefficients(pairing *pbc.Element, coeff_list map[string]*pbc.Element) {

	coeff := pairing.Pairing().NewZr().Set1()
	root.getCoefficientsMap(pairing, coeff_list, coeff)
}

func (subtree *node) getCoefficientsMap(pairing *pbc.Element, coeff_list map[string]*pbc.Element, coeff *pbc.Element) {
	// Empty Node
	if subtree == nil {
		return
	}
	// Leaf Node
	if !isOp((*subtree).val) {
		attr := (*subtree).val
		if (*subtree).dup_label > 0 {
			attr = fmt.Sprintf("%s_%d", attr, (*subtree).dup_label-1)
		}
		coeff_list[attr] = coeff
		return
		// Operator Node
	} else if isOpOr((*subtree).val) {
		(*subtree).left.getCoefficientsMap(pairing, coeff_list, pairing.Pairing().NewZr().Set0().Mul(coeff, recoverCoefficients(pairing, []int32{1})[1]))
		(*subtree).right.getCoefficientsMap(pairing, coeff_list, pairing.Pairing().NewZr().Set0().Mul(coeff, recoverCoefficients(pairing, []int32{1})[1]))
	} else if isOpAnd((*subtree).val) {
		(*subtree).left.getCoefficientsMap(pairing, coeff_list, pairing.Pairing().NewZr().Set0().Mul(coeff, recoverCoefficients(pairing, []int32{1, 2})[1]))
		(*subtree).right.getCoefficientsMap(pairing, coeff_list, pairing.Pairing().NewZr().Set0().Mul(coeff, recoverCoefficients(pairing, []int32{1, 2})[2]))
		// Invalid catch
	} else {
		return
	}
}

func recoverCoefficients(pairing *pbc.Element, list []int32) (this_coeff map[int]*pbc.Element) {

	// Create empty map
	this_coeff = make(map[int]*pbc.Element)

	var list2 []*pbc.Element
	for _, v := range list {
		list2 = append(list2, pairing.Pairing().NewZr().SetInt32(v))
	}

	for i, v1 := range list2 {

		result := pairing.Pairing().NewZr().Set1()
		for _, v2 := range list2 {
			if !(v1.Equals(v2)) {
				//lagrange basis poly
				tmp1 := pairing.Pairing().NewZr().Set0()
				tmp2 := pairing.Pairing().NewZr().Set0()
				tmp1.Sub(pairing.Pairing().NewZr().Set0(), v2)
				tmp2.Sub(v1, v2)
				tmp1.Div(tmp1, tmp2)
				result.Mul(result, tmp1)
			}
		}
		this_coeff[int(list[i])] = result
	}
	return
}

func (root *node) prune(attributes []string) (policySatisfied bool, prunedList []string) {

	policySatisfied, prunedList = root.requiredAttributes(attributes)
	return
}

func (subtree *node) requiredAttributes(attributes []string) (policySatisfied bool, prunedList []string) {

	// Default case policy for node is not satisfied
	policySatisfied = false

	// Empty Node
	if subtree == nil {
		prunedList = []string{}
		return
	}
	// Leaf Node
	if !isOp((*subtree).val) {
		attr := (*subtree).val
		if searchSlice(attributes, attr) {
			policySatisfied = true
			prunedList = []string{attr}
		}
		// Operator Node
	} else if isOpOr((*subtree).val) {
		// Either child needs to return true  for this node to return true

		leftPol, leftPrune := (*subtree).left.requiredAttributes(attributes)
		rightPol, rightPrune := (*subtree).right.requiredAttributes(attributes)

		if leftPol {
			policySatisfied = true
			prunedList = append(prunedList, leftPrune...)
		} else if rightPol {
			policySatisfied = true
			prunedList = append(prunedList, rightPrune...)
		}
	} else if isOpAnd((*subtree).val) {
		// Both children need to return true for this node to return true

		leftPol, leftPrune := (*subtree).left.requiredAttributes(attributes)
		rightPol, rightPrune := (*subtree).right.requiredAttributes(attributes)

		if leftPol && rightPol {
			policySatisfied = true
			prunedList = append(prunedList, leftPrune...)
			prunedList = append(prunedList, rightPrune...)
		}
	}
	return

}

func searchSlice(list []string, element string) (result bool) {
	result = false
	for _, v := range list {
		if element == v {
			result = true
		}
	}
	return
}
