package main

import (
	"errors"
	"gopkg.in/yaml.v3"
)

// Simplified YAML object (can only represent scalars or mappings)
type Object struct {
	Name     string
	Content  string
	Children []Object
}

// Parses a YAML document into an Object
func ParseYAMLDocument(data []byte) (Object, error) {
	var node yaml.Node
	var object Object
	err := yaml.Unmarshal(data, &node)
	if err != nil {
		return object, err
	}
	object, err = nodeToObject(node.Content[0])
	if err != nil {
		return object, err
	}
	return object, nil
}

// Helper function, tries to convert a yaml.Node to an Object
func nodeToObject(node *yaml.Node) (Object, error) {
	if node.Kind != yaml.MappingNode {
		return Object {
			Name:     "",
			Content:  node.Value,
			Children: nil,
		}, nil
	}
	var ch []Object
	for i := 0; i < len(node.Content); i += 2 {
		var obj Object
		if node.Content[i].Tag != "!!str" {
			return obj, errors.New("invalid tag")
		}
		obj, err := nodeToObject(node.Content[i+1])
		if err != nil {
			return obj, err
		}
		obj.Name = node.Content[i].Value
		ch = append(ch, obj)
	}
	return Object {
		Name: "",
		Content: node.Value,
		Children: ch,
	}, nil
}