from invoke import task


@task
def test(ctx, slow=False):
    cmd = """python -m unittest *_test.py"""
    if slow:
        cmd += " *_slowtest.py"
    ctx.run(cmd)


@task
def cover(ctx, src="solutions_test.py"):
    cmd = '''coverage run --omit 'env/*' {src} && coverage html'''.format(src=src)
    ctx.run(cmd)
