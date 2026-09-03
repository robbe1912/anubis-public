extends Node

var game_state = null

func _ready():
    game_state.load_level("res://level_1.tscn")
