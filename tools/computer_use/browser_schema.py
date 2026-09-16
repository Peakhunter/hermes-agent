"""Installed namespaced typed-browser parameters (no authorization grants)."""
BROWSER_PROPERTIES = {'tab_id': {'type': 'string',
            'description': 'Opaque tab capability returned by cua_browser_state.'},
 'ref': {'type': 'string',
         'description': 'Current semantic ref from the latest cua_browser_state snapshot.'},
 'destination_ref': {'type': 'string',
                     'description': 'Current destination ref for a typed pointer action.'},
 'url': {'type': 'string', 'description': 'URL for cua_browser_navigate.'},
 'input_route': {'type': 'string',
                 'enum': ['trusted', 'dom_event'],
                 'description': 'Typed-browser trust class. Defaults to trusted. dom_event is an '
                                'explicit downgrade and is never selected silently.'},
 'snapshot_format': {'type': 'string',
                     'enum': ['semantic_v2', 'dom_refs_v1'],
                     'description': 'Typed-browser snapshot format; semantic_v2 is the default.'},
 'include_screenshot': {'type': 'boolean',
                        'description': 'For cua_browser_state, include the current browser '
                                       'screenshot as image content in the tool result. Defaults '
                                       'to false. Applies to snapshot calls only: passing '
                                       'pid/window_id makes the call a binding, which carries no '
                                       'page content and reports screenshot_deferred instead.'},
 'query': {'type': 'string', 'description': 'Optional browser-state query.'},
 'scope_ref': {'type': 'string', 'description': 'Optional current ref to scope a snapshot.'},
 'continuation': {'type': 'string', 'description': 'Continuation minted by the current snapshot.'},
 'profile_mode': {'type': 'string',
                  'enum': ['isolated_new', 'isolated_named', 'existing_profile'],
                  'description': 'Browser preparation mode. existing_profile is decided by '
                                 "cua-driver's immutable permission mode: in standard mode it "
                                 "requires the user's config opt-in "
                                 'computer_use.grant_existing_profile: true (if refused, report '
                                 'that key to the user — you cannot grant it); bounded mode '
                                 'authorizes via the reviewed capability manifest; explicit Hermes '
                                 'YOLO uses a private unrestricted daemon.'},
 'profile_name': {'type': 'string', 'description': 'Name for isolated_named setup.'},
 'allow_launch': {'type': 'boolean',
                  'description': 'Explicitly allow launch of a driver-owned isolated browser.'},
 'browser_pointer_action': {'type': 'string',
                            'enum': ['hover', 'right_click', 'double_click', 'scroll', 'drag'],
                            'description': 'Operation for cua_browser_pointer.'},
 'browser_dialog_action': {'type': 'string',
                           'enum': ['inspect', 'accept', 'dismiss'],
                           'description': 'Page JavaScript dialog action; native prompts stay on '
                                          'the native ladder.'},
 'browser_type_mode': {'type': 'string',
                       'enum': ['insert_text', 'keystrokes'],
                       'description': 'Delivery form for cua_browser_type; defaults to '
                                      'insert_text.'},
 'replace': {'type': 'boolean',
             'description': "For cua_browser_type, select the target's complete value before "
                            'typing so the supplied text replaces it. Defaults to false; true with '
                            'empty text clears the field.'},
 'dialog_id': {'type': 'string', 'description': 'Opaque page-dialog capability.'},
 'prompt_text': {'type': 'string', 'description': 'Optional text for a page prompt dialog.'},
 'files': {'type': 'array',
           'items': {'type': 'string'},
           'description': 'Explicit paths for cua_browser_set_input_files.'},
 'destination_root': {'type': 'string',
                      'description': 'Approved destination root for cua_browser_download.'},
 'delta_x': {'type': 'number', 'description': 'Typed pointer horizontal delta.'},
 'delta_y': {'type': 'number', 'description': 'Typed pointer vertical delta.'},
 'x': {'type': 'number', 'description': 'Typed browser viewport x coordinate.'},
 'y': {'type': 'number', 'description': 'Typed browser viewport y coordinate.'},
 'to_x': {'type': 'number', 'description': 'Typed browser drag destination x.'},
 'to_y': {'type': 'number', 'description': 'Typed browser drag destination y.'}}
BROWSER_ACTIONS = ['cua_browser_state', 'cua_browser_prepare', 'cua_browser_navigate', 'cua_browser_click', 'cua_browser_type', 'cua_browser_pointer', 'cua_browser_dialog', 'cua_browser_set_input_files', 'cua_browser_download']
