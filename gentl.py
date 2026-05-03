from hatch_build import CustomBuildHook
tl_builder = CustomBuildHook()
tl_builder.root = tl_builder.directory = '.'
tl_builder.initialize('v1', { 'force_include': {} })
