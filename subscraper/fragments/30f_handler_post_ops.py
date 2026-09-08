"""HTTP handler mixin: job/settings POST ops."""
class HandlerPostOpsMixin:
    def _post_ops(self) -> None:
        allowed = {
            "/api/run",
            "/api/settings",
            "/api/api-keys",
            "/api/jobs/pause",
            "/api/jobs/resume",
            "/api/jobs/resume-all",
            "/api/jobs/skip-step",
            "/api/jobs/cancel-all",
            "/api/jobs/delete",
            "/api/import",
            "/api/targets/resume",
            "/api/monitors",
            "/api/monitors/delete",
            "/api/backup/create",
            "/api/backup/restore",
            "/api/backup/delete",
            "/api/cleanup/run",
            "/api/tools/install",
            "/api/subdomain/mark",
            "/api/subdomain/comment",
            "/api/subdomain/run-tool",
            "/api/target/comment",
            "/api/wordlist/upload",
        }
        if self.path not in allowed:
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
            return


        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length else ""
        content_type = self.headers.get("Content-Type", "")

        payload = {}
        try:
            if "application/json" in content_type and body:
                payload = json.loads(body)
            else:
                payload = {k: v[0] for k, v in parse_qs(body).items()}
        except json.JSONDecodeError:
            self._send_json({"success": False, "message": "Invalid JSON payload."}, status=HTTPStatus.BAD_REQUEST)
            return

        if self.path == "/api/wordlist/upload":
            filename = str(payload.get("filename") or "")
            content = payload.get("content")
            if content is None:
                self._send_json({"success": False, "message": "content is required"}, status=HTTPStatus.BAD_REQUEST)
                return
            success, message, path = save_uploaded_wordlist(filename, str(content))
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message, "path": path}, status=status)
            return

        
        if self.path == "/api/backup/create":
            name = payload.get("name", "")
            success, message, filename = create_backup(name if name else None)
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message, "filename": filename}, status=status)
            return
        
        if self.path == "/api/backup/restore":
            filename = payload.get("filename", "")
            if not filename:
                self._send_json({"success": False, "message": "Filename is required"}, status=HTTPStatus.BAD_REQUEST)
                return
            success, message = restore_backup(filename)
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message}, status=status)
            return
        
        if self.path == "/api/backup/delete":
            filename = payload.get("filename", "")
            if not filename:
                self._send_json({"success": False, "message": "Filename is required"}, status=HTTPStatus.BAD_REQUEST)
                return
            success, message = delete_backup(filename)
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message}, status=status)
            return
        
        if self.path == "/api/cleanup/run":
            try:
                stats = run_cleanup()
                total = sum(stats.values())
                message = f"Cleanup completed: {stats['temp_files']} temp files, {stats['scan_results']} scan results, {stats['backups']} backups removed"
                self._send_json({"success": True, "message": message, "stats": stats}, status=HTTPStatus.OK)
            except Exception as exc:
                self._send_json({"success": False, "message": f"Cleanup failed: {str(exc)}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if self.path == "/api/tools/install":
            requested = payload.get("tools") or payload.get("tool") or []
            if isinstance(requested, str):
                requested = [part.strip() for part in re.split(r"[,\s]+", requested) if part.strip()]
            unknown = [name for name in requested if name not in TOOLS]
            if unknown:
                self._send_json({"success": False,
                                 "message": f"Unknown tool(s): {', '.join(unknown)}"},
                                status=HTTPStatus.BAD_REQUEST)
                return
            targets = requested or [name for name in TOOLS.keys()]

            def _install_async() -> None:
                for name in targets:
                    try:
                        ensure_tool_installed(name)
                    except Exception as exc:
                        log(f"Install attempt for {name} failed: {exc}")

            threading.Thread(target=_install_async, name="tool-install", daemon=True).start()
            info = detect_platform()
            self._send_json({
                "success": True,
                "message": (f"Installing {len(targets)} tool(s) on {info['system_label']}. "
                            "Watch Logs for progress, then refresh."),
                "tools": targets,
                "platform": info["system_label"],
            })
            return

        if self.path == "/api/jobs/pause":
            domain = payload.get("domain", "")
            success, message = pause_job(domain)
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message}, status=status)
            return

        if self.path == "/api/jobs/resume":
            domain = payload.get("domain", "")
            success, message = resume_job(domain)
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message}, status=status)
            return

        if self.path == "/api/jobs/resume-all":
            success, message, results = resume_all_paused_jobs()
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message, "results": results}, status=status)
            return
        
        if self.path == "/api/jobs/skip-step":
            domain = payload.get("domain", "")
            step = payload.get("step", "")
            success, message = skip_job_step(domain, step)
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message}, status=status)
            return
        
        if self.path == "/api/jobs/cancel-all":
            success, message, results = cancel_all_jobs()
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message, "results": results}, status=status)
            return

        if self.path == "/api/jobs/delete":
            domain = payload.get("domain", "")
            job_id = payload.get("job_id", "")
            success, message = delete_job(domain=domain, job_id=job_id)
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message}, status=status)
            return


        if self.path == "/api/targets/resume":
            domain = payload.get("domain", "")
            skip_value = payload.get("skip_nikto")
            skip_flag = None
            if skip_value is not None and skip_value != "":
                skip_flag = bool_from_value(skip_value, False)
            wordlist = payload.get("wordlist")
            success, message = resume_target_scan(domain, wordlist=wordlist, skip_nikto=skip_flag)
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message}, status=status)
            return

        if self.path == "/api/run":
            domain = payload.get("domain", "")
            wordlist = payload.get("wordlist")
            interval_val = payload.get("interval")
            interval_int: Optional[int] = None
            if interval_val not in (None, ""):
                try:
                    interval_int = int(interval_val)
                except (TypeError, ValueError):
                    interval_int = None
            skip_default = get_config().get("skip_nikto_by_default", False)
            skip_nikto = bool_from_value(payload.get("skip_nikto"), skip_default)

            success, message, _ = start_targets_from_input(domain, wordlist, skip_nikto, interval_int)
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message}, status=status)
            return

        if self.path == "/api/import":
            content = payload.get("content", "") or ""
            interval_val = payload.get("interval")
            interval_int: Optional[int] = None
            if interval_val not in (None, ""):
                try:
                    interval_int = int(interval_val)
                except (TypeError, ValueError):
                    interval_int = None
            skip_default = get_config().get("skip_nikto_by_default", False)
            skip_nikto = bool_from_value(payload.get("skip_nikto"), skip_default)

            success, message, info = import_domains_and_run(content, skip_nikto, interval_int)
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message, "info": info}, status=status)
            return

        if self.path == "/api/domain/js-scan":
            domain = (payload.get("domain") or "").strip().lower()
            if not domain:
                self._send_json({"success": False, "message": "Domain is required."}, status=HTTPStatus.BAD_REQUEST)
                return
            state = load_state()
            if domain not in state.get("targets", {}):
                self._send_json({"success": False, "message": "Domain not found."}, status=HTTPStatus.NOT_FOUND)
                return
            cfg = get_config()

            def _js_scan_async() -> None:
                try:
                    run_js_scan(domain, cfg, job_domain=None)
                    st = load_state()
                    ensure_target_state(st, domain)["flags"]["js_scan_done"] = True
                    save_state(st)
                except Exception as exc:
                    log(f"Manual JS scan failed for {domain}: {exc}")

            threading.Thread(target=_js_scan_async, name=f"jsscan-{domain}", daemon=True).start()
            self._send_json({"success": True, "message": f"JS scan started for {domain}. Refresh in a moment."})
            return

        if self.path == "/api/monitors":
            name = payload.get("name", "")
            url = payload.get("url", "")
            interval = payload.get("interval")
            success, message, monitor = add_monitor(name, url, interval)
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message, "monitor": monitor}, status=status)
            return

        if self.path == "/api/monitors/delete":
            monitor_id = payload.get("id") or payload.get("monitor_id") or ""
            success, message = remove_monitor(monitor_id)
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message}, status=status)
            return

        if self.path == "/api/api-keys":
            amass_keys = payload.get("amass", {})
            subfinder_keys = payload.get("subfinder", {})
            success, message = save_all_api_keys(amass_keys, subfinder_keys)
            status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self._send_json({"success": success, "message": message}, status=status)
            return

        if self.path == "/api/subdomain/mark":
            domain = payload.get("domain", "").strip().lower()
            subdomain = payload.get("subdomain", "").strip().lower()
            interesting = payload.get("interesting")  # Can be true, false, or null
            
            if not domain or not subdomain:
                self._send_json({"success": False, "message": "Domain and subdomain are required"}, status=HTTPStatus.BAD_REQUEST)
                return
            
            state = load_state()
            target = state.get("targets", {}).get(domain)
            if not target or subdomain not in target.get("subdomains", {}):
                self._send_json({"success": False, "message": "Subdomain not found"}, status=HTTPStatus.NOT_FOUND)
                return
            
            # Update the interesting flag
            sub_data = target["subdomains"][subdomain]
            if interesting is None:
                sub_data.pop("interesting", None)
            else:
                sub_data["interesting"] = bool(interesting)
            
            save_state(state)
            self._send_json({"success": True, "message": "Subdomain marked successfully"})
            return

        if self.path == "/api/subdomain/comment":
            domain = payload.get("domain", "").strip().lower()
            subdomain = payload.get("subdomain", "").strip().lower()
            comment_text = payload.get("comment", "").strip()
            action = payload.get("action", "add")  # add or delete
            comment_id = payload.get("comment_id")
            
            if not domain or not subdomain:
                self._send_json({"success": False, "message": "Domain and subdomain are required"}, status=HTTPStatus.BAD_REQUEST)
                return
            
            state = load_state()
            target = state.get("targets", {}).get(domain)
            if not target or subdomain not in target.get("subdomains", {}):
                self._send_json({"success": False, "message": "Subdomain not found"}, status=HTTPStatus.NOT_FOUND)
                return
            
            sub_data = target["subdomains"][subdomain]
            comments = sub_data.get("comments", [])
            
            if action == "add":
                if not comment_text:
                    self._send_json({"success": False, "message": "Comment text is required"}, status=HTTPStatus.BAD_REQUEST)
                    return
                new_comment = {
                    "id": str(uuid.uuid4()),
                    "text": comment_text,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                comments.append(new_comment)
                sub_data["comments"] = comments
                save_state(state)
                self._send_json({"success": True, "message": "Comment added", "comment": new_comment})
            elif action == "delete":
                if not comment_id:
                    self._send_json({"success": False, "message": "Comment ID is required for delete"}, status=HTTPStatus.BAD_REQUEST)
                    return
                original_count = len(comments)
                comments = [c for c in comments if c.get("id") != comment_id]
                if len(comments) == original_count:
                    self._send_json({"success": False, "message": "Comment not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                sub_data["comments"] = comments
                save_state(state)
                self._send_json({"success": True, "message": "Comment deleted"})
            else:
                self._send_json({"success": False, "message": "Invalid action"}, status=HTTPStatus.BAD_REQUEST)
            return

        if self.path == "/api/subdomain/run-tool":
            domain = payload.get("domain", "").strip().lower()
            subdomain = payload.get("subdomain", "").strip().lower()
            tool = payload.get("tool", "").strip().lower()
            
            if not domain or not subdomain or not tool:
                self._send_json({"success": False, "message": "Domain, subdomain, and tool are required"}, status=HTTPStatus.BAD_REQUEST)
                return
            
            if tool not in ["waybackurls", "gau", "ffuf"]:
                self._send_json({"success": False, "message": "Invalid tool. Allowed: waybackurls, gau, ffuf"}, status=HTTPStatus.BAD_REQUEST)
                return
            
            state = load_state()
            target = state.get("targets", {}).get(domain)
            if not target or subdomain not in target.get("subdomains", {}):
                self._send_json({"success": False, "message": "Subdomain not found"}, status=HTTPStatus.NOT_FOUND)
                return
            
            # Run the tool in a background thread to avoid blocking the UI
            def run_tool_async():
                try:
                    # Execute the tool
                    if tool == "waybackurls":
                        urls = waybackurls_enum(domain, job_domain=None)
                        log(f"waybackurls found {len(urls)} URLs for {domain}")
                    elif tool == "gau":
                        urls = gau_enum(domain, job_domain=None)
                        log(f"gau found {len(urls)} URLs for {domain}")
                    elif tool == "ffuf":
                        config = get_config()
                        wordlist = resolve_wordlist_path(config.get("default_wordlist") or "")
                        if not wordlist or not Path(wordlist).is_file():
                            log(f"ffuf wordlist not configured or not found for {subdomain}")
                            return

                        
                        # Run ffuf for the subdomain
                        log(f"Running ffuf brute-force for {subdomain} using {wordlist}")
                        subs_ffuf = ffuf_bruteforce(subdomain, wordlist, config=config, job_domain=None)
                        log(f"ffuf found {len(subs_ffuf)} vhost subdomains for {subdomain}")
                        
                        # Store the new subdomains found by ffuf using the standard function
                        state = load_state()
                        add_subdomains_to_state(state, domain, subs_ffuf, "ffuf")
                        
                        # Mark ffuf as run for this domain
                        tgt = ensure_target_state(state, domain)
                        if "flags" not in tgt:
                            tgt["flags"] = {}
                        tgt["flags"]["ffuf_done"] = True
                        
                        save_state(state)
                        return
                    else:
                        return
                    
                    # Store endpoints in state (for waybackurls and gau)
                    state = load_state()
                    tgt = ensure_target_state(state, domain)
                    
                    # Initialize endpoints list if it doesn't exist
                    if "endpoints" not in tgt:
                        tgt["endpoints"] = []
                    
                    # Add new URLs to endpoints
                    existing_endpoints = set(tgt.get("endpoints", []))
                    for url in urls:
                        if url and url not in existing_endpoints:
                            tgt["endpoints"].append(url)
                    
                    # Mark tool as done
                    if "flags" not in tgt:
                        tgt["flags"] = {}
                    if tool == "waybackurls":
                        tgt["flags"]["waybackurls_done"] = True
                    elif tool == "gau":
                        tgt["flags"]["gau_done"] = True
                    
                    save_state(state)
                except Exception as e:
                    log(f"Error running {tool} for {domain}/{subdomain}: {e}")
            
            # Start the tool in a background thread
            thread = threading.Thread(target=run_tool_async, daemon=True)
            thread.start()
            
            self._send_json({"success": True, "message": f"{tool} started for {subdomain}. Results will appear shortly."})
            return

        if self.path == "/api/target/comment":
            domain = payload.get("domain", "").strip().lower()
            comment_text = payload.get("comment", "").strip()
            action = payload.get("action", "add")  # add or delete
            comment_id = payload.get("comment_id")
            
            if not domain:
                self._send_json({"success": False, "message": "Domain is required"}, status=HTTPStatus.BAD_REQUEST)
                return
            
            state = load_state()
            target = state.get("targets", {}).get(domain)
            if not target:
                self._send_json({"success": False, "message": "Domain not found"}, status=HTTPStatus.NOT_FOUND)
                return
            
            comments = target.get("comments", [])
            
            if action == "add":
                if not comment_text:
                    self._send_json({"success": False, "message": "Comment text is required"}, status=HTTPStatus.BAD_REQUEST)
                    return
                new_comment = {
                    "id": str(uuid.uuid4()),
                    "text": comment_text,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                comments.append(new_comment)
                target["comments"] = comments
                save_state(state)
                self._send_json({"success": True, "message": "Comment added", "comment": new_comment})
            elif action == "delete":
                if not comment_id:
                    self._send_json({"success": False, "message": "Comment ID is required for delete"}, status=HTTPStatus.BAD_REQUEST)
                    return
                original_count = len(comments)
                comments = [c for c in comments if c.get("id") != comment_id]
                if len(comments) == original_count:
                    self._send_json({"success": False, "message": "Comment not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                target["comments"] = comments
                save_state(state)
                self._send_json({"success": True, "message": "Comment deleted"})
            else:
                self._send_json({"success": False, "message": "Invalid action"}, status=HTTPStatus.BAD_REQUEST)
            return

        success, message, cfg = update_config_settings(payload)
        status = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
        self._send_json({"success": success, "message": message, "config": cfg}, status=status)

