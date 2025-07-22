package utils

func GetStringFromMap(m map[string]any, key string) string {
	if value, ok := m[key]; ok {
		if strValue, ok := value.(string); ok {
			return strValue
		}
	}
	return ""
}

func GetIntFromMap(m map[string]any, key string) int {
	if value, ok := m[key]; ok {
		if intValue, ok := value.(int); ok {
			return intValue
		} else if floatValue, ok := value.(float64); ok {
			return int(floatValue)
		}
	}
	return 0
}
