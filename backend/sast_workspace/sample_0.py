def serialize_value(
        value: T,
        *,
        key: str | None = None,
        task_id: str | None = None,
        dag_id: str | None = None,
        run_id: str | None = None,
        map_index: int | None = None,
    ) -> bytes | str:
        # we will always serialize ourselves and not by BaseXCom as the deserialize method
        # from BaseXCom accepts only XCom objects and not the value directly
        s_val = json.dumps(value, cls=XComEncoder).encode("utf-8")

        if compression := _get_compression():
            suffix = f".{_get_compression_suffix(compression)}"
        else:
            suffix = ""

        threshold = _get_threshold()
        if threshold < 0 or len(s_val) < threshold:  # Either no threshold or value is small enough.
            return s_val

        base_path = _get_base_path()
        while True:  # Safeguard against collisions.
            p = base_path.joinpath(dag_id, run_id, task_id, f"{uuid.uuid4()}{suffix}")
            if not p.exists():
                break
        p.parent.mkdir(parents=True, exist_ok=True)

        with p.open(mode="wb", compression=compression) as f:
            f.write(s_val)
        return BaseXCom.serialize_value(str(p))