extends Node2D

signal health_changed

func _ready():
    health_changed.emit()
