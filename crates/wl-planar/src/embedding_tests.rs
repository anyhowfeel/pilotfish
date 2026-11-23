use super::*;

/// Wheel on 5 vertices: hub 0, rim 1..=4. Planar, 5 faces.
fn wheel() -> (Graph, Embedding) {
    let g = Graph::new(
        5,
        &[
            (0, 1),
            (0, 2),
            (0, 3),
            (0, 4),
            (1, 2),
            (2, 3),
            (3, 4),
            (4, 1),
        ],
    );
    let e = Embedding::new(vec![
        vec![1, 2, 3, 4],
        vec![0, 4, 2],
        vec![0, 1, 3],
        vec![0, 2, 4],
        vec![0, 3, 1],
    ]);
    (g, e)
}

#[test]
fn a_wheel_has_five_faces_and_satisfies_euler() {
    let (g, e) = wheel();
    assert_eq!(e.faces().len(), 5);
    assert!(e.is_planar_embedding(&g));
}

#[test]
fn a_wrong_rotation_breaks_euler() {
    let (g, _) = wheel();
    // Swapping two neighbours at the hub folds the wheel onto a surface with a handle.
    let bad = Embedding::new(vec![
        vec![1, 3, 2, 4],
        vec![0, 4, 2],
        vec![0, 1, 3],
        vec![0, 2, 4],
        vec![0, 3, 1],
    ]);
    assert!(!bad.is_planar_embedding(&g));
}

#[test]
fn rotations_must_match_the_neighbours() {
    let (g, _) = wheel();
    let missing = Embedding::new(vec![
        vec![1, 2, 3],
        vec![0, 4, 2],
        vec![0, 1, 3],
        vec![0, 2, 4],
        vec![0, 3, 1],
    ]);
    assert!(!missing.is_planar_embedding(&g));
    assert!(!Embedding::new(vec![vec![]]).is_planar_embedding(&g));
}

#[test]
fn a_tree_has_one_face_and_a_path_is_planar() {
    let g = Graph::new(4, &[(0, 1), (1, 2), (1, 3)]);
    let e = Embedding::new(vec![vec![1], vec![0, 2, 3], vec![1], vec![1]]);
    assert_eq!(e.faces().len(), 1);
    assert_eq!(e.faces()[0].len(), 6);
    assert!(e.is_planar_embedding(&g));
}

#[test]
fn components_and_isolated_vertices_are_checked_separately() {
    let g = Graph::new(6, &[(0, 1), (2, 3), (3, 4), (4, 2)]);
    let e = Embedding::new(vec![
        vec![1],
        vec![0],
        vec![3, 4],
        vec![2, 4],
        vec![3, 2],
        vec![],
    ]);
    assert!(e.is_planar_embedding(&g));
}

#[test]
fn k4_has_four_faces_in_its_planar_embedding() {
    let g = Graph::new(4, &[(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)]);
    let e = Embedding::new(vec![
        vec![1, 2, 3],
        vec![0, 3, 2],
        vec![0, 1, 3],
        vec![0, 2, 1],
    ]);
    assert_eq!(e.faces().len(), 4);
    assert!(e.is_planar_embedding(&g));
}
