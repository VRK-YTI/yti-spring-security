package fi.vm.yti.security.util;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static java.util.Collections.unmodifiableMap;
import static java.util.Collections.unmodifiableSet;

public final class CollectionUtil {

    private CollectionUtil() {
    }

    public static <K, V> Map<K, Set<V>> unmodifiable(final Map<K, Set<V>> map) {

        for (final K key : new ArrayList<>(map.keySet())) {
            map.put(key, unmodifiableSet(map.get(key)));
        }

        return unmodifiableMap(map);
    }

    public static <K, V> Set<V> getOrInitializeSet(final Map<K, Set<V>> map,
                                                   final K key) {

        final Set<V> set = map.get(key);

        if (set != null) {
            return set;
        } else {
            final HashSet<V> newSet = new HashSet<>();
            map.put(key, newSet);
            return newSet;
        }
    }
}
