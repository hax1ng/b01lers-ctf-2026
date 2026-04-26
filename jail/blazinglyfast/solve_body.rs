fn lt_mut<'a, 'b, T: ?Sized>(_: &'a &'b (), v: &'b mut T) -> &'a mut T { v }
fn expand_mut<'a, 'b, T: ?Sized>(x: &'a mut T) -> &'b mut T {
    let f: for<'x> fn(_, &'x mut T) -> &'b mut T = lt_mut;
    f(&&(), x)
}

enum D<A, B> { A(Option<Box<A>>), B(Option<Box<B>>) }

fn transmute_inner<A, B>(dummy: &mut D<A, B>, obj: A) -> B {
    let ref_to_b = match dummy {
        D::B(r) => r,
        _ => loop {},
    };
    let ref_to_b: &mut Option<Box<B>> = expand_mut(ref_to_b);
    *dummy = D::A(Some(Box::new(obj)));
    core::hint::black_box(dummy);
    *ref_to_b.take().unwrap()
}

fn trans<A, B>(obj: A) -> B {
    transmute_inner(core::hint::black_box(&mut D::B(None)), obj)
}

trans::<In, Out>(input)
