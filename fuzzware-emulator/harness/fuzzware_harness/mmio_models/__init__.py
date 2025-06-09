def parse_mmio_model_config(uc, config):
    if 'mmio_models' in config and config['mmio_models']:
        if 'constant' in config['mmio_models']:
            from .constant import parse_constant_handlers, register_constant_mmio_models
            register_constant_mmio_models(uc, *parse_constant_handlers(uc.symbols, config['mmio_models']['constant']))

        if 'passthrough' in config['mmio_models']:
            from .passthrough import (parse_passthrough_handlers,
                          register_passthrough_handlers)
            register_passthrough_handlers(uc, *parse_passthrough_handlers(uc.symbols, config['mmio_models']['passthrough']))

        if 'linear' in config['mmio_models']:
            from .linear import parse_linear_handlers, register_linear_mmio_models
            register_linear_mmio_models(uc, *parse_linear_handlers(uc.symbols, config['mmio_models']['linear']))

        if 'bitextract' in config['mmio_models']:
            from .bitextract import (parse_bitextract_handlers,
                         register_bitextract_mmio_models)
            register_bitextract_mmio_models(uc, *parse_bitextract_handlers(uc.symbols, config['mmio_models']['bitextract']))

        if 'set' in config['mmio_models']:
            from .set import parse_value_set_handlers, register_value_set_mmio_models
            register_value_set_mmio_models(uc, *parse_value_set_handlers(uc.symbols, config['mmio_models']['set']))

        if 'custom' in config['mmio_models']:
            from .wrapper import register_custom_handlers
            register_custom_handlers(uc, config['mmio_models']['custom'])
